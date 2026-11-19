"""Data models for normalized log events and correlated security alerts."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LogEvent:
    """Represents a parsed and normalized authentication log entry.

    Attributes:
        timestamp: Raw timestamp extracted from the syslog header.
        service: Originating daemon or service name (e.g., ``sshd``).
        status: Authentication outcome (e.g., ``FAILED`` or ``ACCEPTED``).
        user: Target username involved in the authentication attempt.
        source_ip: Originating IPv4/IPv6 address of the connection.
        raw_line: Original unparsed log line for forensic traceability.
    """

    timestamp: str
    service: str
    status: str
    user: str
    source_ip: str
    raw_line: str


@dataclass
class SecurityAlert:
    """Represents a security anomaly triggered by event correlation rules.

    Attributes:
        rule_name: Identifier of the detection rule that triggered the alert.
        severity: Alert criticality level (e.g., ``MEDIUM``, ``HIGH``, ``CRITICAL``).
        source_ip: Attacker or anomalous source IP address.
        attempt_count: Total number of matching events observed within the threshold.
        targeted_users: Deduplicated list of usernames targeted by the source IP.
        detected_at: ISO-8601 timestamp indicating when the alert was generated.
    """

    rule_name: str
    severity: str
    source_ip: str
    attempt_count: int
    targeted_users: list[str] = field(default_factory=list)
    detected_at: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )