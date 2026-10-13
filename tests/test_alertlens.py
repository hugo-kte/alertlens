from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alertlens.cli import app
from alertlens.correlate import correlate
from alertlens.enrich import Context
from alertlens.evaluate import run, stratified_sample, verdict_metrics
from alertlens.faithfulness import unsupported_claims
from alertlens.ingest import parse, read_alerts
from alertlens.llm import ScriptedModel
from alertlens.models import Alert, Verdict
from alertlens.playbooks import Library
from alertlens.triage import Triager, explain

ROOT = Path(__file__).parents[1]
T0 = datetime(2017, 7, 5, 12, 0, tzinfo=UTC)


def alert(
    minutes: float,
    src="10.9.9.9",
    family="DoS",
    detector="supervised",
    truth="DoS Hulk",
    dst="192.168.10.50",
    **kw,
) -> Alert:
    return Alert(
        T0 + timedelta(minutes=minutes),
        src,
        dst,
        80,
        "tcp",
        family,
        detector,
        73,
        technique_id=kw.get("technique", "T1499"),
        attack_probability=kw.get("p", 0.99),
        anomaly_ratio=kw.get("ratio"),
        ground_truth=truth,
    )


def ecs(minutes: float, src: str, family: str, detector: str, truth: str) -> dict:
    return {
        "@timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
        "event": {"severity": 73},
        "source": {"ip": src, "port": 40000},
        "destination": {"ip": "192.168.10.50", "port": 80},
        "network": {"transport": "tcp"},
        "flowguard": {
            "family": family,
            "detector": detector,
            "attack_probability": 0.99,
            "anomaly_ratio": 1.2,
            "explanation": ["SYN flags = 1"],
            "ground_truth": truth,
        },
        "threat": {"technique": {"id": "T1499"}},
    }


@pytest.fixture(scope="module")
def library() -> Library:
    return Library.load(ROOT / "playbooks")


@pytest.fixture(scope="module")
def context() -> Context:
    return Context.load(ROOT / "configs" / "assets.yaml")


def test_ingest_ecs_and_eve(tmp_path):
    a = parse(ecs(0, "1.2.3.4", "DoS", "both", "DoS Hulk"))
    assert a.family == "DoS" and a.technique_id == "T1499" and a.ground_truth == "DoS Hulk"
    eve = parse(
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "event_type": "alert",
            "src_ip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {"category": "Detection of a Network Scan", "severity": 2},
        }
    )
    assert eve.family == "PortScan" and eve.severity == 70 and eve.ground_truth is None
    assert parse({"event_type": "flow"}) is None
    path = tmp_path / "a.jsonl.gz"
    with gzip.open(path, "wt") as fh:
        for m in (5, 0):
            fh.write(json.dumps(ecs(m, "1.2.3.4", "DoS", "both", "DoS Hulk")) + "\n")
    assert [x.ts for x in read_alerts(path)] == sorted(x.ts for x in read_alerts(path))


def test_correlation_groups_by_source_family_and_gap():
    alerts = [
        alert(0),
        alert(10),
        alert(25),
        alert(100),
        alert(5, src="10.8.8.8"),
        alert(6, family="PortScan"),
    ]
    incidents = correlate(alerts, gap=timedelta(minutes=30))
    sizes = sorted(i.size for i in incidents)
    assert sizes == [1, 1, 1, 3]  # the 100-minute alert opens a new incident


def test_facts_never_contain_ground_truth():
    inc = correlate([alert(0, truth="BENIGN"), alert(1, truth="DoS Hulk")])[0]
    assert "BENIGN" not in json.dumps(inc.facts()) and "Hulk" not in json.dumps(inc.facts())
    assert inc.truth == "attack"  # ties go to attack: missing one costs more


def test_enrichment_uses_inventory_and_scope(context):
    facts = correlate([alert(0, src="203.0.113.7")])[0].facts()
    enriched = context.enrich(facts)
    assert enriched["source"] == {"ip": "203.0.113.7", "scope": "external"}
    assert enriched["destinations"][0]["name"] == "web-01"
    assert enriched["techniques"][0]["name"] == "Endpoint Denial of Service"
    assert "source_ip" not in enriched


def test_playbooks_parse_and_route(library):
    dos = library.retrieve("DDoS", [])
    assert dos.id == "PB-DOS" and "DOS-C1" in dos.steps and "Containment" in dos.sections
    assert library.retrieve("Unknown", ["T1110"]).id == "PB-BRUTE"
    assert library.retrieve("Unknown", [], "beaconing to a remote endpoint").id == "PB-C2"
    assert all(pb.steps for pb in library.playbooks)


def test_rules_baseline(library, context):
    triager = Triager(None, library, context)
    flood = correlate([alert(m, detector="both") for m in range(3)])[0]
    lone = correlate([alert(0, family="Anomaly", detector="anomaly", technique=None)])[0]
    assert triager.rules(flood).decision.verdict is Verdict.TRUE_POSITIVE
    assert triager.rules(flood).decision.action_step_ids  # escalations cite steps
    assert triager.rules(lone).decision.verdict is Verdict.FALSE_POSITIVE


def answer(**over):
    base = {
        "verdict": "true_positive",
        "confidence": 0.9,
        "severity": "high",
        "summary": "Flood against web-01 from 10.9.9.9.",
        "technique_ids": ["T1499"],
        "action_step_ids": ["DOS-T1", "DOS-C1"],
        "rationale": "many alerts",
    }
    return base | over


def test_llm_output_is_validated_and_grounded(library, context):
    model = ScriptedModel(
        lambda _: answer(action_step_ids=["DOS-T1", "DOS-Z9"], technique_ids=["T1499", "T9999"])
    )
    res = Triager(model, library, context).llm(correlate([alert(0)])[0])
    assert res.decision.action_step_ids == ["DOS-T1"] and res.hallucinated_steps == ["DOS-Z9"]
    assert res.decision.technique_ids == ["T1499"] and res.hallucinated_techniques == ["T9999"]
    assert "Playbook" in model.calls[0] and "DOS-C1" in model.calls[0]


def test_llm_retries_then_falls_back_to_rules(library, context):
    replies = iter(["not json", answer(action_step_ids=[]), answer()])
    model = ScriptedModel(lambda _: next(replies))
    res = Triager(model, library, context).llm(correlate([alert(0)])[0], retries=1)
    assert (
        res.triager == "llm-fallback" and res.attempts == 2
    )  # escalation without steps is invalid
    ok = Triager(ScriptedModel(lambda _: answer()), library, context).llm(correlate([alert(0)])[0])
    assert ok.triager == "llm:scripted" and ok.attempts == 1


def test_hybrid_keeps_the_rules_verdict(library, context):
    model = ScriptedModel(
        lambda _: {
            "summary": "Isolated anomaly.",
            "technique_ids": [],
            "action_step_ids": ["ANO-T1"],
        }
    )
    lone = correlate([alert(0, family="Anomaly", detector="anomaly", technique=None)])[0]
    res = explain(Triager(model, library, context), lone)
    assert (
        res.decision.verdict is Verdict.FALSE_POSITIVE
        and res.decision.summary == "Isolated anomaly."
    )
    assert "Verdict (fixed): false_positive" in model.calls[0]


def test_faithfulness_checker(context):
    facts = context.enrich(correlate([alert(0, src="203.0.113.7")])[0].facts())
    names = {a.name for a in context.assets.values()}
    assert unsupported_claims("Flood from 203.0.113.7 against web-01 (T1499).", facts, names) == []
    issues = unsupported_claims(
        "dc-01 scanned by 198.51.100.1 using Network Service Discovery", facts, names
    )
    assert set(issues) == {
        "asset:dc-01",
        "ip:198.51.100.1",
        "technique_name:Network Service Discovery",
    }


def synthetic_alerts(path: Path) -> Path:
    with path.open("w") as fh:
        for m in range(6):
            fh.write(json.dumps(ecs(m, "203.0.113.7", "DoS", "both", "DoS Hulk")) + "\n")
        for k in range(8):
            fh.write(
                json.dumps(ecs(100 + 60 * k, f"192.168.10.{k + 5}", "Anomaly", "anomaly", "BENIGN"))
                + "\n"
            )
    return path


def test_evaluation_end_to_end(tmp_path):
    path = synthetic_alerts(tmp_path / "alerts.jsonl")
    model = ScriptedModel(
        lambda prompt: (
            answer() if '"DoS"' in prompt else answer(verdict="false_positive", action_step_ids=[])
        )
    )
    m = run(
        path,
        model,
        playbooks=ROOT / "playbooks",
        assets=ROOT / "configs/assets.yaml",
        n_benign=5,
        out_dir=tmp_path / "reports",
    )
    assert m["incidents"] == 9 and m["sample"]["incidents"] == 6
    llm = m["configs"]["llm"]
    assert llm["escalation_recall"] == 1.0 and llm["fp_closure_rate"] == 1.0
    assert (tmp_path / "reports" / "triage_results.jsonl").exists()
    incidents = correlate(read_alerts(path))
    assert len(stratified_sample(incidents, 2)) == 3
    assert verdict_metrics([])["escalation_recall"] is None


def test_cli_incidents_and_rules_triage(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    runner = CliRunner()
    path = synthetic_alerts(tmp_path / "alerts.jsonl")
    result = runner.invoke(app, ["incidents", str(path)])
    assert result.exit_code == 0 and "9 incidents" in result.output.replace("\n", " ")
    out = tmp_path / "triage.md"
    result = runner.invoke(app, ["triage", str(path), "--mode", "rules", "-o", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert "PB-DOS" in text and "true positive" in text
    assert out.with_suffix(".jsonl").read_text().count("\n") == 9


def test_step_ids_written_with_their_text_are_normalised(library, context):
    from alertlens.triage import normalise_steps

    assert normalise_steps(
        ["DOS-C1: Rate-limit the sources", "`DOS-T1`", "DOS-C1", "nonsense"]
    ) == [
        "DOS-C1",
        "DOS-T1",
        "nonsense",
    ]
    model = ScriptedModel(lambda _: answer(action_step_ids=["DOS-T1: Confirm impact", "DOS-Q7"]))
    res = Triager(model, library, context).llm(correlate([alert(0)])[0])
    assert res.decision.action_step_ids == ["DOS-T1"] and res.hallucinated_steps == ["DOS-Q7"]
