# 🛡 CyberlsonLog AI — Intelligent Log Anomaly Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/OWASP-Top10%20Mitigated-blue?style=flat-square)
![Defensive](https://img.shields.io/badge/Purpose-100%25%20Defensive-brightgreen?style=flat-square)

**An enterprise-grade AI-powered security monitoring system that ingests system logs, detects anomalies using Isolation Forest machine learning, scores risk, and generates professional threat analysis reports.**

[Features](#features) · [Architecture](#architecture) · [Quick Start](#quick-start) · [ML Model](#ml-model) · [Security](#security-design) · [Deployment](#deployment) · [Recruiter Value](#recruiter-value)

</div>

---

> **⚠️ Defensive Purpose Statement**
> CyberlsonShield is a strictly defensive security tool. It contains no exploit code, attack automation, malware logic, or penetration testing capabilities. Its sole purpose is log anomaly detection and security monitoring.

---

## Screenshots

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡 CyberlsonShield                   ● SYSTEM ONLINE // DEFENSIVE MODE │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│           Intelligent Log Anomaly Detection                       │
│                                                                   │
│  ┌─ Drop Zone ──────────────────────────────────────────────┐   │
│  │  📄 Drop your log file here                              │   │
│  │     .log · .txt | max 10 MB                              │   │
│  │              [ Browse Files ]                             │   │
│  └───────────────────────────────────────────────────────────┘   │
│  [ ▶ Run AI Analysis ]                                           │
│                                                                   │
│  ┌─ Risk Score ─────────────────┐ ┌─ Ring Gauge ─┐ ┌─ Bars ─┐  │
│  │  OVERALL SYSTEM RISK SCORE   │ │    ( 73.2 )   │ │ ML  ██▌│  │
│  │  73.2 / 100                  │ │      High     │ │ Auth██ │  │
│  │  HIGH RISK                   │ └───────────────┘ └────────┘  │
│  └──────────────────────────────┘                               │
│                                                                   │
│  [Log Events] [Windows] [Anomalies] [High Risk] [Failed Auth]   │
│                                                                   │
│  ─── Anomaly Score Timeline ─────────────────────────────────── │
│  1.0 ┤                      ▲                                   │
│  0.65┤ - - - - - - - - - - -│- - - - (High Risk threshold)      │
│  0.35┤ - - - - - - - - - (Suspicious threshold)                 │
│  0.0 ┤──────────────────────────────────────────────            │
│                                                                   │
│  ─── Top Suspicious IPs ─────  ─── Failed Auth Over Time ─────  │
│   10.0.0.55      ████ 0.89    │   08:02 ████████████████ 6     │
│   45.33.32.156   ████ 0.81    │   08:04 ██████████ 5           │
│   172.16.254.1   ████ 0.76    │   02:15 █████████████ 6        │
│                                                                   │
│  ─── Defensive Recommendations ──────────────────────────────── │
│  [HIGH] Authentication Hardening: 17 failed auth events          │
│  [HIGH] WAF Deployment: SQL injection patterns detected           │
│  [HIGH] IP Threat Response: Block 10.0.0.55, 45.33.32.156       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Log Upload & Parsing Engine
- Accepts `.log` and `.txt` files (up to 10 MB)
- Auto-detects log format: Apache/Nginx combined, syslog, auth.log, generic timestamped
- Extracts: timestamp, IP address, username, event type, HTTP status code, message payload
- Sanitizes all parsed values with `bleach` to prevent XSS via log injection
- Validates IP addresses using Python's `ipaddress` stdlib
- Hard limit: 100,000 lines max to prevent memory exhaustion

### Feature Engineering
- **Event frequency**: request burst detection via statistical thresholding
- **Failed authentication counts**: per-window and cumulative IP-level tallies
- **Off-hours detection**: flags activity between 22:00 and 06:00
- **HTTP error rate**: proportion of 4xx/5xx responses per window
- **Suspicious keyword rate**: detects SQL patterns, path traversal, known attack strings
- **IP behavioral context**: log-scaled cumulative threat weighting per source IP
- **12 numerical features** fed to the Isolation Forest model

### AI Anomaly Detection
- **Algorithm**: Scikit-learn Isolation Forest (unsupervised)
- **Training**: Fresh model trained on each uploaded log (no stale state)
- **Contamination**: Auto-tuned based on dataset size
- **Scoring**: Raw scores normalized to [0, 1]; higher = more anomalous
- **Labels**: Normal / Suspicious / High Risk (threshold-based)
- **Explainability**: Rule-based plain-English explanation per flagged window

### Risk Scoring Engine
- **Composite score** (0–100) from four weighted components:
  - ML anomaly score (40%)
  - Failed auth density (25%)
  - Suspicious event concentration (20%)
  - Off-hours anomaly fraction (15%)
- **Risk tiers**: Low / Medium / High / Critical
- Per-IP risk ranking and cross-log behavioral aggregation

### Dashboard
- Anomaly score timeline chart (Plotly)
- Top suspicious IPs bar chart (color-coded by severity)
- Failed auth events histogram over time
- Summary statistics cards
- Animated SVG ring gauge for overall risk score
- Risk component breakdown bars

### Report Generator
- Professional PDF report via ReportLab
- Executive summary, key metrics table, IP analysis table
- Defensive recommendations with priority levels
- Served as a download, deleted from server immediately after

---

## Architecture

```
CyberlsonShield/
│
├── app/
│   ├── __init__.py          # Flask factory, security headers middleware
│   ├── routes.py            # HTTP endpoints, file validation, pipeline orchestration
│   ├── log_parser.py        # Multi-format log parsing, sanitization
│   ├── feature_engineering.py  # Behavioral feature extraction (Pandas/NumPy)
│   ├── anomaly_model.py     # Isolation Forest training, scoring, explainability
│   └── risk_engine.py       # Risk scoring, findings, PDF report generation
│
├── templates/
│   └── index.html           # Single-page dashboard (Plotly, vanilla JS)
│
├── static/                  # CSS, JS, images
│
├── sample_logs/
│   ├── sample_apache.log    # Realistic Apache access log with embedded threats
│   └── sample_auth.log      # Realistic syslog/auth.log with brute-force patterns
│
├── config.py                # Environment-variable-based configuration
├── run.py                   # Application entry point
├── gunicorn.conf.py         # Production WSGI server configuration
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── DEPLOYMENT.md
```

### Request Flow

```
Browser → Nginx (TLS termination, rate limiting, static files)
       → Gunicorn (WSGI worker pool)
       → Flask (security headers, route dispatch)
       → log_parser (format detection, sanitization)
       → feature_engineering (12 behavioral features, time windows)
       → anomaly_model (StandardScaler + IsolationForest)
       → risk_engine (composite scoring, findings, PDF)
       → JSON response → Dashboard renders charts
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- pip

### Installation

```bash
git clone https://github.com/yourusername/CyberlsonShield.git
cd CyberlsonShield

python3 -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Generate and set SECRET_KEY in .env:
python -c "import secrets; print(secrets.token_hex(32))"
```

### Run

```bash
python run.py
# Open http://127.0.0.1:5000
```

### Test with Sample Logs

Upload either file from `sample_logs/`:
- `sample_apache.log` — Simulates web server logs with embedded brute-force and injection attempts
- `sample_auth.log` — Simulates SSH authentication log with credential-stuffing patterns

---

## ML Model

### Algorithm: Isolation Forest

Isolation Forest is an unsupervised anomaly detection algorithm particularly well-suited for log analysis:

**How it works:**
1. Builds an ensemble of random binary decision trees (isolation trees)
2. Anomalous points are isolated (reach leaf nodes) with fewer splits than normal points
3. The anomaly score is the average path length across all trees — shorter = more anomalous

**Why it's appropriate for log data:**
- No labeled training data required (we don't need pre-tagged "attack" logs)
- Handles high-dimensional tabular features well
- Scales linearly with dataset size
- Naturally handles the sparsity of security-relevant events
- Contamination parameter provides an interpretable "expected anomaly budget"

**Feature matrix (12 features):**

| Feature | Description |
|---------|-------------|
| `log_event_count` | Log-scaled request count per 5-minute window |
| `failed_auth_count` | Raw failed authentication events in window |
| `failed_auth_rate` | Fraction of events that are failed auths |
| `suspicious_count` | Events matching SQL/traversal/attack patterns |
| `suspicious_rate` | Fraction of suspicious events |
| `http_error_rate` | Fraction of 4xx/5xx HTTP responses |
| `unique_event_types` | Diversity of event types (low = monotonous scanning) |
| `is_off_hours` | Binary: activity between 22:00 and 06:00 |
| `is_burst` | Binary: event count > 2σ above mean |
| `ip_failed_auth_weight` | Log-scaled cumulative failed auths from this IP |
| `ip_suspicious_weight` | Log-scaled cumulative suspicious events from this IP |
| `mean_status` | Average HTTP status code |

**Explainability:**
Each flagged window receives a human-readable explanation generated by rule-based logic applied to the raw feature values — making the model's decisions transparent without requiring SHAP or LIME.

---

## Security Design

CyberlsonShield was built to OWASP Top 10 (2021) standards.

| Threat | Mitigation |
|--------|-----------|
| A01: Broken Access Control | File operations use `secure_filename()`, absolute paths, no user-controlled path components |
| A02: Cryptographic Failures | `SECRET_KEY` from environment variable; HTTPS enforced by Nginx |
| A03: Injection | All log values sanitized via `bleach`; no `eval()`/`exec()` in parser; parameterized operations only |
| A04: Insecure Design | File size hard cap (10 MB); 100K line limit; extension whitelist |
| A05: Security Misconfiguration | Debug mode off in production; security headers on every response |
| A06: Vulnerable Components | Pinned dependency versions in `requirements.txt` |
| A07: Auth Failures | Session signing via `SECRET_KEY`; Nginx rate limiting on `/analyze` |
| A08: Software & Data Integrity | No shell commands in pipeline; `preload_app=True` in Gunicorn |
| A09: Logging Failures | Structured logging; request details logged without sensitive values |
| A10: SSRF | No outbound HTTP requests made by the application |

**Security Headers applied to every response:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` (strict allowlist)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Strict-Transport-Security` (via Nginx in production)

**File Lifecycle:**
1. Upload → saved with UUID prefix to isolated `uploads/` directory
2. Analysis pipeline runs
3. File deleted in `finally` block regardless of success/failure
4. PDF reports deleted immediately after serving the download response

---

## API Reference

### `POST /analyze`
Upload and analyze a log file.

**Request:** `multipart/form-data`
- `logfile`: `.log` or `.txt` file (max 10 MB)

**Response (200):**
```json
{
  "risk": {
    "score": 73.2,
    "tier": "High",
    "color": "#ea580c",
    "components": {
      "ml_anomaly_component": 62.1,
      "failed_auth_component": 85.0,
      "suspicious_events_component": 40.3,
      "off_hours_component": 100.0
    }
  },
  "summary": { "total_log_entries": 52, "anomalous_windows": 4, ... },
  "timeline": [{ "window": "2024-01-10 08:00", "max_score": 0.891, ... }],
  "top_suspicious_ips": [{ "ip": "10.0.0.55", "risk_label": "High Risk", ... }],
  "recommendations": [{ "priority": "High", "category": "...", "action": "..." }]
}
```

### `POST /report`
Generate a PDF report from analysis results.

**Request:** `application/json` (body = response from `/analyze`)

**Response:** PDF file download

### `GET /health`
Health check.
```json
{"status": "ok", "service": "CyberlsonShield"}
```

---

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for full instructions covering:
- Local development
- Ubuntu VPS with Gunicorn + Nginx
- HTTPS with Let's Encrypt
- Systemd service with security hardening
- Render and Railway cloud deployment

---

## Recruiter Value

### Cybersecurity Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| Log Analysis | Multi-format parser (Apache, syslog, auth.log) with regex extraction and timestamp normalization |
| Threat Detection | Isolation Forest model with behavioral feature engineering; rule-based signature matching |
| OWASP Top 10 | Input validation, path traversal prevention, CSP headers, secure file handling — all documented in code comments |
| Blue Team Mindset | Defensive-only design; every feature maps to a SOC analyst workflow |
| Risk Scoring | Hybrid ML + rule-based composite scoring with explainable components |
| Incident Response | Findings output maps directly to containment and hardening actions |
| Security Engineering | Secure SDLC practices: no hardcoded secrets, input sanitization, least-privilege deployment |

### AI/ML Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| Unsupervised Learning | Isolation Forest for anomaly detection without labeled data |
| Feature Engineering | 12 domain-specific behavioral features from raw log text |
| Model Explainability | Rule-based natural language explanations per flagged window |
| Statistical Analysis | Z-score burst detection, log-normalization, time-window aggregation |
| Production ML | StandardScaler preprocessing, contamination tuning, reproducible random state |
| Python Data Stack | Pandas, NumPy, Scikit-learn in a production Flask pipeline |

### Role Alignment

| Role | Alignment |
|------|-----------|
| **SOC Analyst** | Log analysis, alert triage, risk scoring, and report generation mirror daily SOC workflows |
| **Security Data Analyst** | Feature engineering on security telemetry; behavioral analysis; dashboard visualization |
| **Blue Team Engineer** | Defensive tooling, threat detection pipeline, OWASP-compliant implementation |
| **Threat Intelligence Analyst** | IP reputation analysis, pattern recognition, IOC surfacing from log data |
| **AI Security Engineer** | ML model integration into a security product with explainable outputs and production deployment |

---

## GitHub Description

> AI-powered log anomaly detection system. Parses Apache/syslog/auth logs, extracts behavioral features, runs Isolation Forest ML, scores risk, and generates PDF threat reports. Built with Flask + Scikit-learn. Strictly defensive. OWASP Top 10 mitigated.

## GitHub Tags

`python` `flask` `machine-learning` `anomaly-detection` `cybersecurity` `log-analysis` `isolation-forest` `blue-team` `soc` `threat-detection` `security-monitoring` `scikit-learn` `pandas` `devops` `nginx` `gunicorn`

---

## LinkedIn Announcement Post

---

🛡 **Excited to share CyberlsonShield** — an AI-powered log anomaly detection system I built end-to-end.

The idea: bridge the gap between raw system logs and actionable threat intelligence, using machine learning — not just rule-based matching.

**What it does:**
📋 Ingests Apache, Nginx, syslog, and auth.log files
🔬 Extracts 12 behavioral features per time window (failed auth rates, request bursts, off-hours activity, suspicious patterns)
🤖 Trains an **Isolation Forest** model on each upload for unsupervised anomaly detection
📊 Scores each IP and time window on a 0–100 risk scale with plain-English explanations
📄 Generates a downloadable PDF threat analysis report with defensive recommendations

**Tech stack:** Python 3.11 · Flask · Scikit-learn · Pandas · Plotly · ReportLab · Gunicorn · Nginx

**Security-first design:**
- All inputs sanitized with `bleach`
- Files deleted immediately after analysis
- OWASP Top 10 mitigations documented in code
- Security headers on every response
- Deployed behind Nginx with TLS and rate limiting

This project demonstrates skills directly applicable to SOC Analyst, Security Data Analyst, Blue Team Engineer, and AI Security Engineer roles.

Check it out on GitHub: [link]

#Cybersecurity #MachineLearning #PythonDeveloper #BlueTeam #SOC #AnomalyDetection #SecurityEngineering #OpenSource

---

## License

MIT License. See `LICENSE` for details.

---

*CyberlsonShield is an educational and defensive security tool. It contains no offensive security capabilities, exploit code, or attack automation of any kind.*
