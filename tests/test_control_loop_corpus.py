"""The exported corpus preserves evidence without exporting evaluation answers."""

import json
import subprocess
import sys
from pathlib import Path

from evals.cases.control_loop import SCENARIOS


def test_export_control_loop_corpus(tmp_path: Path) -> None:
    output = tmp_path / "corpus.jsonl"
    subprocess.run(
        [sys.executable, "-m", "scripts.export_control_loop_corpus", "--out", str(output)],
        check=True,
    )
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(rows) == len(SCENARIOS)
    for row, scenario in zip(rows, SCENARIOS, strict=True):
        assert set(row) == {"id", "replayed_at", "environment", "service", "evidence_inputs", "expected_root_cause"}
        assert row["id"] == scenario.id
        assert row["expected_root_cause"] == scenario.expected_root_cause
        assert row["evidence_inputs"] == json.loads(json.dumps(scenario.evidence_inputs, default=str))
        assert row["replayed_at"] == str(scenario.replayed_at)
        assert row["environment"] == scenario.environment
        assert row["service"] == scenario.service
