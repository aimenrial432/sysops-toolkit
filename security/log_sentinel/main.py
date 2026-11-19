"""CLI entrypoint for Log Sentinel streaming log analyzer."""

import argparse
import sys
from pathlib import Path

from security.log_sentinel.pipeline import (
    detect_bruteforce,
    parse_ssh_events,
    stream_lines,
)
from security.log_sentinel.reporter import export_json_report, print_console_report


def parse_args() -> argparse.Namespace:
    """Parses command-line arguments for Log Sentinel."""
    parser = argparse.ArgumentParser(
        description="Streaming SSH authentication log triage using Python generators."
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to the target auth log file (e.g., /var/log/auth.log).",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Failed login attempts required to trigger an alert (default: 5).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to export alerts in JSON format.",
    )
    return parser.parse_args()


def main() -> None:
    """Runs the streaming log analysis pipeline and outputs results."""
    args = parse_args()
    log_file = Path(args.file)

    if not log_file.is_file():
        print(f"\033[1;31m[-] Error: Log file not found -> {log_file}\033[0m", file=sys.stderr)
        sys.exit(1)

    # Assemble the lazy generator pipeline
    raw_lines = stream_lines(log_file)
    parsed_events = parse_ssh_events(raw_lines)
    alert_stream = detect_bruteforce(parsed_events, threshold=args.threshold)

    # Consume the generator pipeline
    alerts = list(alert_stream)

    print_console_report(alerts, str(log_file))

    if args.output:
        export_json_report(alerts, args.output)


if __name__ == "__main__":
    main()