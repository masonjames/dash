"""CLI entry point: python -m evals"""

import argparse
import json
import sys

from dotenv import load_dotenv

load_dotenv()

from evals import CATEGORIES  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Dash evals")
    subparsers = parser.add_subparsers(dest="command")

    # --- Default (no subcommand): existing Agno evals ---
    parser.add_argument(
        "--category",
        type=str,
        choices=list(CATEGORIES.keys()),
        help="Run a single eval category",
    )
    parser.add_argument("--verbose", action="store_true", help="Show response previews and failure reasons")

    # --- Smoke tests ---
    smoke_parser = subparsers.add_parser("smoke", help="Run lightweight smoke tests")
    from evals.smoke import TESTS

    all_groups = sorted(set(t.group for t in TESTS))
    smoke_parser.add_argument(
        "--group",
        type=str,
        choices=all_groups,
        help=f"Run only one test group ({', '.join(all_groups)})",
    )
    smoke_parser.add_argument("--verbose", "-v", action="store_true", help="Show full responses")
    smoke_parser.add_argument("--user-id", type=str, default="smoke-test@dash.dev", help="User ID for tests")

    # --- Improvement loop ---
    improve_parser = subparsers.add_parser("improve", help="Run self-improvement loop")
    improve_parser.add_argument("--rounds", type=int, default=3, help="Number of improvement rounds (default: 3)")
    improve_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    improve_parser.add_argument("--dry-run", action="store_true", help="Analyze only, don't apply changes")

    # --- Deterministic Ops control-loop replay ---
    replay_parser = subparsers.add_parser(
        "control-loop",
        help="Run synthetic deterministic control-loop contract replays (no model calls)",
    )
    replay_parser.add_argument("--verbose", "-v", action="store_true", help="Show each labeled scenario")
    replay_parser.add_argument("--json", action="store_true", help="Emit the machine-readable report")

    args = parser.parse_args()

    if args.command == "smoke":
        from evals.smoke import run_smoke_tests

        results = run_smoke_tests(group=args.group, verbose=args.verbose, user_id=args.user_id)
        sys.exit(1 if any(r.status != "PASS" for r in results) else 0)

    elif args.command == "improve":
        from evals.improve import run_improvement_loop

        success = run_improvement_loop(rounds=args.rounds, verbose=args.verbose, dry_run=args.dry_run)
        sys.exit(0 if success else 1)

    elif args.command == "control-loop":
        from evals.control_loop import print_report, run_control_loop_replay

        report = run_control_loop_replay(verbose=args.verbose)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, default=str))
        else:
            print_report(report)
        sys.exit(0 if report.gate_passed else 1)

    else:
        # Default: run existing Agno evals
        from evals.run import run_evals

        success = run_evals(category=args.category, verbose=args.verbose)
        sys.exit(0 if success else 1)


main()
