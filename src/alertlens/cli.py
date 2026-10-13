"""AlertLens command-line interface."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Literal

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

app = typer.Typer(
    help="AlertLens - LLM-assisted SOC alert triage.", no_args_is_help=True, add_completion=False
)
console = Console()

AlertsArg = Annotated[
    Path, typer.Argument(exists=True, dir_okay=False, help="Alerts (JSONL[.gz]).")
]
PLAYBOOKS, ASSETS = Path("playbooks"), Path("configs/assets.yaml")


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False)],
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)


@app.command()
def incidents(alerts: AlertsArg, gap_minutes: int = 30, show: int = 15) -> None:
    """Correlate alerts into incidents and list the largest ones."""
    from datetime import timedelta

    from alertlens.correlate import correlate
    from alertlens.ingest import read_alerts

    items = read_alerts(alerts)
    found = correlate(items, timedelta(minutes=gap_minutes))
    console.print(f"{len(items):,} alerts -> [bold]{len(found)}[/bold] incidents")
    table = Table()
    for col in ("incident", "family", "source", "alerts", "first seen", "detectors"):
        table.add_column(col)
    for inc in sorted(found, key=lambda i: -i.size)[:show]:
        f = inc.facts()
        table.add_row(
            inc.id,
            inc.family,
            inc.src_ip,
            str(inc.size),
            f["first_seen"],
            json.dumps(f["detectors"]),
        )
    console.print(table)


@app.command()
def triage(
    alerts: AlertsArg,
    mode: Annotated[str, typer.Option(help="rules | llm | hybrid")] = "hybrid",
    model: str = "llama3.2:3b",
    ollama_url: str = "http://localhost:11434",
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("runtime/triage.md"),
    limit: Annotated[int | None, typer.Option(help="Triage only the N largest incidents.")] = None,
    include_closed: bool = False,
) -> None:
    """Triage incidents and write analyst tickets (Markdown) + decisions (JSONL)."""
    from alertlens.correlate import correlate
    from alertlens.enrich import Context
    from alertlens.ingest import read_alerts
    from alertlens.llm import OllamaModel
    from alertlens.playbooks import Library
    from alertlens.report import tickets
    from alertlens.triage import Triager, explain

    chosen: Literal["rules", "llm", "hybrid"] = mode  # type: ignore[assignment]
    found = correlate(read_alerts(alerts))
    if limit:
        found = sorted(found, key=lambda i: -i.size)[:limit]
    library = Library.load(PLAYBOOKS)
    triager = Triager(
        None if chosen == "rules" else OllamaModel(model, ollama_url), library, Context.load(ASSETS)
    )
    results = []
    with console.status("triaging...") as status:
        for k, inc in enumerate(found, 1):
            status.update(f"triaging {inc.id} ({k}/{len(found)})")
            if chosen == "rules":
                results.append(triager.rules(inc))
            elif chosen == "llm":
                results.append(triager.llm(inc))
            else:
                results.append(explain(triager, inc))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(tickets(results, library, include_closed), encoding="utf-8")
    with out.with_suffix(".jsonl").open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(
                json.dumps(
                    {
                        "incident": r.incident.id,
                        "triager": r.triager,
                        "playbook": r.playbook_id,
                        "decision": r.decision.model_dump(mode="json"),
                    }
                )
                + "\n"
            )
    escalated = sum(r.decision.verdict.escalated for r in results)
    console.print(f"{len(results)} incidents: [bold]{escalated}[/bold] escalated -> {out}")


@app.command()
def evaluate(
    alerts: Annotated[Path, typer.Argument(exists=True)] = Path(
        "examples/flowguard_alerts.jsonl.gz"
    ),
    model: str = "llama3.2:3b",
    ollama_url: str = "http://localhost:11434",
    n_benign: int = 40,
    out_dir: Path = Path("reports"),
) -> None:
    """Compare rules, LLM and hybrid triage against ground truth; write reports/."""
    from alertlens import plots, report
    from alertlens.evaluate import run
    from alertlens.llm import OllamaModel

    m = run(alerts, OllamaModel(model, ollama_url), n_benign=n_benign, out_dir=out_dir)
    plots.comparison(m["configs"], out_dir / "figures" / "triage_comparison.png")
    (out_dir / "REPORT.md").write_text(report.evaluation(m), encoding="utf-8")
    console.print(f"Report: [bold]{out_dir / 'REPORT.md'}[/bold]")


if __name__ == "__main__":
    app()
