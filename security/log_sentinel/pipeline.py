"""Streaming log processing pipeline built with chained Python generators."""

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

from security.log_sentinel.models import LogEvent, SecurityAlert

# Matches standard OpenSSH syslog entries for Failed/Accepted authentication,
# explicitly distinguishing between existing and non-existent (invalid) users.
SSH_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+(?P<service>sshd)\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+\S+\s+for\s+"
    r"(?:invalid user\s+(?P<invalid_user>\S+)|(?P<valid_user>\S+))\s+"
    r"from\s+(?P<ip>\S+)"
)


def stream_lines(file_path: str | Path) -> Iterator[str]:
    """Yields lines lazily from a log file without loading it into memory.

    Args:
        file_path: Path to the target log file.

    Yields:
        Stripped raw log lines one at a time.

    Raises:
        FileNotFoundError: If the specified log file does not exist.
    """
    path = Path(file_path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            cleaned = line.rstrip("\r\n")
            if cleaned:
                yield cleaned


def parse_ssh_events(lines: Iterable[str]) -> Iterator[LogEvent]:
    """Parses raw syslog lines into normalized LogEvent instances.

    Non-matching lines (e.g., cron, kernel, or session close messages) are
    silently skipped to keep the stream clean.

    Args:
        lines: An iterable or generator yielding raw log strings.

    Yields:
        Structured LogEvent objects for valid SSH authentication entries.
    """
    for line in lines:
        match = SSH_LOG_PATTERN.search(line)
        if not match:
            continue

        target_user = match.group("invalid_user") or match.group("valid_user")

        yield LogEvent(
            timestamp=match.group("timestamp"),
            service=match.group("service"),
            status=match.group("status").upper(),
            user=target_user,
            source_ip=match.group("ip"),
            raw_line=line,
        )


def detect_bruteforce(
    events: Iterable[LogEvent],
    threshold: int = 5,
) -> Iterator[SecurityAlert]:
    """Correlates failed login events and yields alerts when thresholds are met.

    Args:
        events: An iterable or generator yielding LogEvent objects.
        threshold: Minimum number of failed attempts from a single IP required
            to trigger a SecurityAlert. Defaults to 5.

    Yields:
        SecurityAlert objects as soon as an IP reaches the failure threshold.
    """
    attempts_by_ip: dict[str, list[str]] = defaultdict(list)
    alerted_ips: set[str] = set()

    for event in events:
        if event.status != "FAILED":
            continue

        attempts_by_ip[event.source_ip].append(event.user)
        current_count = len(attempts_by_ip[event.source_ip])

        if current_count >= threshold and event.source_ip not in alerted_ips:
            alerted_ips.add(event.source_ip)
            unique_users = list(dict.fromkeys(attempts_by_ip[event.source_ip]))
            severity = "CRITICAL" if "root" in unique_users else "HIGH"

            yield SecurityAlert(
                rule_name="SSH_BRUTEFORCE_THRESHOLD",
                severity=severity,
                source_ip=event.source_ip,
                attempt_count=current_count,
                targeted_users=unique_users,
            )