"""CLI entry point: python -m evals control-loop."""

import argparse
import json

from evals.control_loop import print_report, run_control_loop_replay


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Ops contract replays")
    subparsers = parser.add_subparsers(dest="command", required=True)
    replay_parser = subparsers.add_parser(
        "control-loop",
        help="Run synthetic deterministic control-loop contract replays (no model calls)",
    )
    replay_parser.add_argument("--verbose", "-v", action="store_true", help="Show each labeled scenario")
    replay_parser.add_argument("--json", action="store_true", help="Emit the machine-readable report")
    args = parser.parse_args()

    report = run_control_loop_replay(verbose=args.verbose)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print_report(report)
    raise SystemExit(0 if report.gate_passed else 1)


if __name__ == "__main__":
    main()
