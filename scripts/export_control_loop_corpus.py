"""Export synthetic canonical evidence and independent root-cause labels as JSONL."""

import argparse
import json
from pathlib import Path

from evals.cases.control_loop import SCENARIOS


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    with args.out.open("w", encoding="utf-8") as output:
        for scenario in SCENARIOS:
            row = {
                "id": scenario.id,
                "replayed_at": scenario.replayed_at,
                "environment": scenario.environment,
                "service": scenario.service,
                "evidence_inputs": scenario.evidence_inputs,
                "expected_root_cause": scenario.expected_root_cause,
            }
            output.write(json.dumps(row, default=str, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
