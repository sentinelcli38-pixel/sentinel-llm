"""Local-only review API for Sentinel reports and scan execution."""
import json
import threading
from pathlib import Path

import typer
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from sentinel.comparison import compare_ledgers
from sentinel.config import settings
from sentinel.plugins import MonitorPluginConfig, plugin_catalog
from sentinel.review import ReviewRecord, list_reviews, save_review
from sentinel.schemas.state import RuntimeState
from sentinel.service import run_scan
from sentinel.telemetry import RunTelemetry

app = FastAPI(title="Sentinel Local Review API", version="0.1.0")
RUNS: dict[str, RunTelemetry] = {}
PLUGIN_CONFIG: MonitorPluginConfig | None = None


class ScanRequest(BaseModel):
    project_path: str = Field(min_length=1)
    mock: bool = False
    scout_only: bool = False
    max_retries: int = Field(default=settings.max_retries, ge=0, le=5)


class ScanResponse(BaseModel):
    final_state: str
    report_path: str | None
    ledger_name: str | None
    findings: int
    confirmed: int
    feedback: list[str]


class RunResponse(BaseModel):
    run_id: str
    status: str


class ReviewDecision(BaseModel):
    decision: str
    rationale: str = Field(min_length=1)


def _reports() -> list[Path]:
    output = settings.output_dir.resolve()
    return sorted(output.glob("sentinel-report-*.json"), reverse=True) if output.is_dir() else []


def _response(state: RuntimeState) -> ScanResponse:
    outcome = state.final_verification_state
    if outcome == "verified" and (not state.judge_result or state.judge_result.evidence_version != 1):
        outcome = "legacy_verification_requires_rescan"
    return ScanResponse(
        final_state=outcome,
        report_path=state.final_report_path,
        ledger_name=Path(state.final_report_path).with_suffix(".json").name if state.final_report_path else None,
        findings=len(state.findings),
        confirmed=sum(f.status.value == "confirmed" for f in state.findings),
        feedback=state.feedback,
    )


def _load_report(report_name: str) -> RuntimeState:
    if Path(report_name).name != report_name or not report_name.endswith(".json"):
        raise HTTPException(status_code=404, detail="Report not found")
    path = settings.output_dir.resolve() / report_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return RuntimeState.model_validate_json(path.read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "scope": "local-only"}


@app.get("/plugins")
def list_plugins() -> list[dict[str, object]]:
    return plugin_catalog()


@app.post("/plugins/onchain-monitor")
def configure_monitor_plugin(config: MonitorPluginConfig) -> dict[str, object]:
    global PLUGIN_CONFIG
    PLUGIN_CONFIG = config
    return {"status": "configured", "enabled": False, "note": "No RPC connection was attempted."}


@app.post("/scans", response_model=ScanResponse)
def create_scan(request: ScanRequest) -> ScanResponse:
    try:
        state = run_scan(
            Path(request.project_path), mock=request.mock,
            scout_only=request.scout_only, max_retries=request.max_retries,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _response(state)


@app.post("/runs", response_model=RunResponse)
def create_run(request: ScanRequest) -> RunResponse:
    telemetry = RunTelemetry()
    RUNS[telemetry.run_id] = telemetry

    def worker() -> None:
        try:
            state = run_scan(Path(request.project_path), mock=request.mock, scout_only=request.scout_only,
                             max_retries=request.max_retries, telemetry=telemetry)
            telemetry.finish("completed", f"Assessment finished: {state.final_verification_state}")
        except ValueError as exc:
            telemetry.finish("failed", str(exc))
        except Exception as exc:  # noqa: BLE001 - API worker boundary
            telemetry.finish("failed", f"Unexpected assessment failure: {exc}")

    threading.Thread(target=worker, name=f"sentinel-{telemetry.run_id[:8]}", daemon=True).start()
    return RunResponse(run_id=telemetry.run_id, status=telemetry.status)


@app.get("/runs/{run_id}", response_model=RunResponse)
def get_run(run_id: str) -> RunResponse:
    telemetry = RUNS.get(run_id)
    if not telemetry:
        raise HTTPException(status_code=404, detail="Run not found")
    snapshot = telemetry.snapshot()
    return RunResponse(run_id=run_id, status=str(snapshot["status"]))


@app.get("/runs/{run_id}/events")
def stream_run_events(run_id: str) -> StreamingResponse:
    telemetry = RUNS.get(run_id)
    if not telemetry:
        raise HTTPException(status_code=404, detail="Run not found")

    def events():
        last_id = 0
        while True:
            with telemetry.condition:
                if not any(int(event["id"]) > last_id for event in telemetry.events) and telemetry.status not in {"completed", "failed"}:
                    telemetry.condition.wait(timeout=15)
                pending = [event for event in telemetry.events if int(event["id"]) > last_id]
                status = telemetry.status
            for event in pending:
                last_id = int(event["id"])
                yield f"id: {last_id}\nevent: update\ndata: {json.dumps(event)}\n\n"
            if status in {"completed", "failed"}:
                return
            if not pending:
                yield ": keepalive\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


@app.get("/scans")
def list_scans() -> list[ScanResponse]:
    records: list[ScanResponse] = []
    for path in _reports():
        try:
            records.append(_response(RuntimeState.model_validate_json(path.read_text(encoding="utf-8"))))
        except ValueError:
            continue
    return records


@app.get("/scans/compare")
def compare_scans(base: str, current: str) -> dict[str, object]:
    return compare_ledgers(_load_report(base), _load_report(current))


@app.get("/scans/{report_name}")
def get_scan(report_name: str) -> RuntimeState:
    return _load_report(report_name)


@app.get("/reviews")
def get_reviews() -> list[ReviewRecord]:
    return list_reviews(settings.output_dir.resolve())


@app.post("/reviews", response_model=ReviewRecord)
def create_review(record: ReviewRecord) -> ReviewRecord:
    _load_report(record.ledger_name)
    return save_review(settings.output_dir.resolve(), record)


@app.post("/reviews/{review_id}", response_model=ReviewRecord)
def decide_review(review_id: str, decision: ReviewDecision) -> ReviewRecord:
    record = next((item for item in list_reviews(settings.output_dir.resolve()) if item.id == review_id), None)
    if not record:
        raise HTTPException(status_code=404, detail="Review not found")
    record.decision, record.rationale = decision.decision, decision.rationale
    return save_review(settings.output_dir.resolve(), record)


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(Path(__file__).with_name("web") / "index.html")


def main(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the API on loopback by default; it is not an authentication service."""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    typer.run(main)
