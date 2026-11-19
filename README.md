# SysOps & Security Toolkit

[![CI - Test Suite](https://github.com/aimenrial432/sysops-toolkit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aimenrial432/sysops-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13-blue?logo=python&logoColor=white)
![Architecture](https://img.shields.io/badge/Architecture-Streaming%20Generators-success)

A modular collection of lightweight, dependency-minimal Python CLI utilities designed for system administration, network diagnostics, and defensive log triage.

## Architecture

The repository is organized by operational domain, with isolated unit tests mirroring the module structure:

```text
sysops-toolkit/
├── .github/workflows/       # Automated CI test pipeline
├── security/
│   └── log_sentinel/        # Streaming SSH authentication log analyzer
├── sample_data/             # Sanitized log fixtures for local testing
├── tests/
│   └── security/            # Unit tests for security modules
└── pyproject.toml           # Pytest and project configuration
```

## Modules

### 1. `security/log_sentinel`

A streaming log triage engine built with chained Python generators (`yield`) to process large authentication logs with constant memory overhead (`O(1)` file buffering).

- **Lazy Pipeline:** `stream_lines` -> `parse_ssh_events` -> `detect_bruteforce`
- **Detection Logic:** Aggregates failed login attempts per source IP, deduplicates targeted usernames, and escalates alert severity to `CRITICAL` when `root` is targeted.
- **Reporting:** Outputs structured terminal alerts and clean, ANSI-free JSON reports.

#### Usage

```bash
python -m security.log_sentinel.main \
  -f sample_data/auth_sample.log \
  -t 5 \
  -o reports/sentinel_report.json
```

## Running Tests

```bash
pytest -v
```
