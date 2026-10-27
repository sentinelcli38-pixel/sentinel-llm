import json
from pathlib import Path

import typer

from sentinel.modeling.data import audit_dataset, prepare_dataset
from sentinel.modeling.properties import prepare_properties

app = typer.Typer(help="Prepare and audit local security-model training data.")


@app.command("prepare-properties")
def prepare_property_data(
    corpus: Path = typer.Option(Path("datasets/cgt"), exists=True, file_okay=False),  # noqa: B008
    previous: Path = typer.Option(Path("datasets/smartbugs-curated"), exists=True, file_okay=False),  # noqa: B008
    output: Path = typer.Option(Path("datasets/model-properties")),  # noqa: B008
    seed: int = 73,
) -> None:
    try:
        typer.echo(json.dumps(prepare_properties(corpus, previous, output, seed), indent=2))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("prepare")
def prepare(
    corpus: Path = typer.Option(Path("datasets/smartbugs-curated"), exists=True, file_okay=False),  # noqa: B008
    output: Path = typer.Option(Path("datasets/model-training")),  # noqa: B008
    seed: int = 42,
) -> None:
    typer.echo(json.dumps(prepare_dataset(corpus, output, seed), indent=2))


@app.command("audit")
def audit(directory: Path = typer.Argument(..., exists=True, file_okay=False)) -> None:  # noqa: B008
    try:
        typer.echo(json.dumps(audit_dataset(directory), indent=2))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
