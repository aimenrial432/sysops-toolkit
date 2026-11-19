"""Unit tests for the Log Sentinel streaming pipeline."""

from security.log_sentinel.pipeline import detect_bruteforce, parse_ssh_events


def test_parse_ssh_events_handles_valid_and_invalid_users() -> None:
    """Ensures both existing and non-existent usernames are extracted cleanly."""
    raw_lines = [
        "Nov 19 10:15:01 host sshd[101]: Accepted publickey for oier from 10.0.0.2 port 22 ssh2",
        "Nov 19 10:16:10 host sshd[102]: Failed password for invalid user admin from 45.33.22.11 port 33412 ssh2",
        "Nov 19 10:17:00 host CRON[200]: (root) CMD (run-parts /etc/cron.hourly)",
    ]

    events = list(parse_ssh_events(raw_lines))

    assert len(events) == 2
    assert events[0].status == "ACCEPTED"
    assert events[0].user == "oier"
    assert events[1].status == "FAILED"
    assert events[1].user == "admin"


def test_detect_bruteforce_escalates_severity_for_root() -> None:
    """Verifies alert generation at threshold and CRITICAL escalation when root is targeted."""
    raw_lines = [
        "Nov 19 10:16:10 host sshd[102]: Failed password for invalid user guest from 1.2.3.4 port 1001 ssh2",
        "Nov 19 10:16:11 host sshd[102]: Failed password for root from 1.2.3.4 port 1002 ssh2",
        "Nov 19 10:16:12 host sshd[102]: Failed password for invalid user test from 1.2.3.4 port 1003 ssh2",
    ]

    alerts = list(detect_bruteforce(parse_ssh_events(raw_lines), threshold=3))

    assert len(alerts) == 1
    assert alerts[0].source_ip == "1.2.3.4"
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].targeted_users == ["guest", "root", "test"]