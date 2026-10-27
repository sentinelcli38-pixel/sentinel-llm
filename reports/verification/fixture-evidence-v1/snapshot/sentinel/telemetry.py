"""Thread-safe, local-only telemetry for an in-flight Sentinel assessment."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class RunTelemetry:
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: str = "queued"
    events: list[dict[str, object]] = field(default_factory=list)
    condition: threading.Condition = field(default_factory=lambda: threading.Condition(threading.RLock()))

    def emit(self, category: str, status: str, summary: str, **details: object) -> None:
        with self.condition:
            self.status = "running" if status == "started" else self.status
            self.events.append({
                "id": len(self.events) + 1,
                "category": category,
                "status": status,
                "summary": summary,
                "timestamp": time.time(),
                "details": details,
            })
            self.condition.notify_all()

    def finish(self, status: str, summary: str) -> None:
        with self.condition:
            self.status = status
            self.events.append({
                "id": len(self.events) + 1,
                "category": "run",
                "status": status,
                "summary": summary,
                "timestamp": time.time(),
                "details": {},
            })
            self.condition.notify_all()

    def snapshot(self) -> dict[str, object]:
        with self.condition:
            return {"run_id": self.run_id, "status": self.status, "events": list(self.events[-100:])}
