"""
app/log_parser.py – Secure Log Parsing Engine
================================================
Parses common log formats (Apache/Nginx combined, syslog, auth.log, generic)
into a structured pandas DataFrame.

Security measures:
  - All string values are sanitized via bleach to remove HTML/script injection
  - Regex-based extraction prevents eval() or exec() usage
  - Invalid lines are skipped rather than raising exceptions
  - IP addresses validated against ipaddress stdlib to prevent injection
  - No shell commands invoked during parsing
"""

import re
import ipaddress
import logging
import pandas as pd
import bleach

logger = logging.getLogger(__name__)

# ── Regex Patterns ─────────────────────────────────────────────────────────────
# Apache/Nginx Combined Log Format:
# 127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'          # IP address
    r'\S+\s+'                   # ident (ignored)
    r'(?P<user>\S+)\s+'        # username
    r'\[(?P<timestamp>[^\]]+)\]\s+'  # timestamp
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'  # request
    r'(?P<status>\d{3})\s+'    # HTTP status code
    r'(?P<size>\S+)'            # response size
)

# Syslog format:
# Jan 10 07:15:55 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22
SYSLOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)'
)

# Generic: timestamp, level, message with optional IP
GENERIC_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'
    r'(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|NOTICE|ALERT|EMERGENCY)?\s*'
    r'(?P<message>.+)'
)

# IP extraction from any string
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Keywords that indicate security-relevant events
FAILED_AUTH_KEYWORDS = re.compile(
    r'(failed|failure|invalid|incorrect|bad|wrong|denied|refused|unauthorized|blocked)',
    re.IGNORECASE
)
SUSPICIOUS_KEYWORDS = re.compile(
    r'(sql|select|union|exec|script|alert|drop table|base64|wget|curl|etc/passwd|'
    r'\.\.\/|traversal|injection|overflow)',
    re.IGNORECASE
)


def _sanitize(value: str) -> str:
    """
    Strip HTML tags and escape dangerous characters from any parsed string value.
    Prevents stored XSS if log content is rendered in the dashboard.
    Uses bleach with an empty allowed-tags list → all HTML stripped.
    """
    if not isinstance(value, str):
        return str(value)
    return bleach.clean(value, tags=[], strip=True)[:512]  # hard length cap


def _validate_ip(ip_str: str) -> str | None:
    """
    Validate IP address using Python's ipaddress stdlib.
    Returns None if the string is not a valid IP.
    Prevents IP-based injection by rejecting malformed values.
    """
    try:
        ipaddress.ip_address(ip_str.strip())
        return ip_str.strip()
    except ValueError:
        return None


def _detect_format(lines: list[str]) -> str:
    """
    Heuristically determine the dominant log format from the first 20 lines.
    Returns: 'apache' | 'syslog' | 'generic'
    """
    scores = {"apache": 0, "syslog": 0, "generic": 0}
    sample = lines[:20]
    for line in sample:
        if APACHE_PATTERN.match(line):
            scores["apache"] += 1
        elif SYSLOG_PATTERN.match(line):
            scores["syslog"] += 1
        elif GENERIC_PATTERN.match(line):
            scores["generic"] += 1
    return max(scores, key=scores.get)


def _parse_apache_line(line: str) -> dict | None:
    m = APACHE_PATTERN.match(line)
    if not m:
        return None
    ip = _validate_ip(m.group("ip"))
    if not ip:
        return None
    try:
        status = int(m.group("status"))
    except ValueError:
        status = 0
    message = f'{m.group("method")} {m.group("path")}'
    return {
        "timestamp_raw": _sanitize(m.group("timestamp")),
        "ip": ip,
        "user": _sanitize(m.group("user")),
        "event_type": "http_request",
        "status_code": status,
        "message": _sanitize(message),
        "is_failed_auth": status in (401, 403),
        "is_suspicious": bool(SUSPICIOUS_KEYWORDS.search(m.group("path"))),
    }


def _parse_syslog_line(line: str) -> dict | None:
    m = SYSLOG_PATTERN.match(line)
    if not m:
        return None
    msg = m.group("message")
    ips = IP_RE.findall(msg)
    ip = _validate_ip(ips[0]) if ips else "0.0.0.0"
    service = _sanitize(m.group("service"))
    timestamp_raw = f'{m.group("month")} {m.group("day")} {m.group("time")}'
    user_match = re.search(r'for\s+(\S+)\s+from', msg)
    user = _sanitize(user_match.group(1)) if user_match else "unknown"
    return {
        "timestamp_raw": _sanitize(timestamp_raw),
        "ip": ip or "0.0.0.0",
        "user": user,
        "event_type": _sanitize(service),
        "status_code": 0,
        "message": _sanitize(msg),
        "is_failed_auth": bool(FAILED_AUTH_KEYWORDS.search(msg)),
        "is_suspicious": bool(SUSPICIOUS_KEYWORDS.search(msg)),
    }


def _parse_generic_line(line: str) -> dict | None:
    m = GENERIC_PATTERN.match(line)
    if not m:
        return None
    msg = m.group("message") or ""
    ips = IP_RE.findall(msg)
    ip = _validate_ip(ips[0]) if ips else "0.0.0.0"
    return {
        "timestamp_raw": _sanitize(m.group("timestamp")),
        "ip": ip or "0.0.0.0",
        "user": "unknown",
        "event_type": _sanitize(m.group("level") or "log"),
        "status_code": 0,
        "message": _sanitize(msg),
        "is_failed_auth": bool(FAILED_AUTH_KEYWORDS.search(msg)),
        "is_suspicious": bool(SUSPICIOUS_KEYWORDS.search(msg)),
    }


def parse_log_file(filepath: str) -> pd.DataFrame:
    """
    Main entry point. Read a log file and return a structured DataFrame.

    Args:
        filepath: Absolute path to the validated, uploaded log file.

    Returns:
        pd.DataFrame with columns:
            timestamp_raw, ip, user, event_type, status_code,
            message, is_failed_auth, is_suspicious, timestamp

    Raises:
        ValueError: If file cannot be parsed into any known format.
    """
    # ── Read File Safely ───────────────────────────────────────────────────────
    # Open with explicit encoding; replace undecodable bytes to avoid crashes.
    # Hard limit: only read first 100,000 lines to prevent memory exhaustion.
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            lines = [fh.readline() for _ in range(100_000)]
        lines = [l.rstrip("\n") for l in lines if l.strip()]
    except OSError as exc:
        raise ValueError(f"Cannot read log file: {exc}") from exc

    if not lines:
        raise ValueError("Log file is empty or contains no readable lines.")

    fmt = _detect_format(lines)
    logger.info("Detected log format: %s (%d lines)", fmt, len(lines))

    parsers = {
        "apache": _parse_apache_line,
        "syslog": _parse_syslog_line,
        "generic": _parse_generic_line,
    }
    parser_fn = parsers[fmt]

    records = []
    skipped = 0
    for line in lines:
        row = parser_fn(line)
        if row:
            records.append(row)
        else:
            skipped += 1

    logger.info("Parsed %d records; skipped %d unparseable lines.", len(records), skipped)

    if not records:
        raise ValueError(
            "No lines could be parsed. Ensure the file is a valid .log or .txt "
            "in Apache, syslog, or timestamped generic format."
        )

    df = pd.DataFrame(records)
    # ── Timestamp Normalization ────────────────────────────────────────────────
    # Convert raw timestamp strings to pandas datetime for time-series analysis.

    if fmt == "apache":
        df["timestamp"] = pd.to_datetime(
            df["timestamp_raw"],
            format="%d/%b/%Y:%H:%M:%S %z",
            errors="coerce",
        )
    else:
        from datetime import datetime

        current_year = datetime.now().year

        df["timestamp"] = pd.to_datetime(
            str(current_year) + " " + df["timestamp_raw"],
            format="%Y %b %d %H:%M:%S",
            errors="coerce",
        )
    # Drop rows with invalid timestamps
    df = df.dropna(subset=["timestamp"])

    print("Rows after timestamp conversion:", len(df))
    print(df[["timestamp_raw", "timestamp"]].head())

    if df.empty:
        raise ValueError(
            "All log entries had invalid timestamps. Check the log format."
        )

    df = df.sort_values("timestamp").reset_index(drop=True)

    return df
