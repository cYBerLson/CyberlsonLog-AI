# gunicorn.conf.py – Production Gunicorn Configuration
# ======================================================
# Run with: gunicorn --config gunicorn.conf.py run:application

import multiprocessing
import os

# ── Binding ────────────────────────────────────────────────────────────────────
# Bind to localhost only; Nginx proxies traffic externally.
# Never bind to 0.0.0.0 without a reverse proxy and firewall.
bind = "127.0.0.1:5000"

# ── Workers ────────────────────────────────────────────────────────────────────
# Formula: (2 × CPU_count) + 1 is a common heuristic for CPU-bound apps.
workers = int(os.environ.get("GUNICORN_WORKERS", (2 * multiprocessing.cpu_count()) + 1))

# Worker class: sync is appropriate for this CPU-bound ML workload.
worker_class = "sync"

# ── Timeouts ───────────────────────────────────────────────────────────────────
# ML analysis can take several seconds on large files; allow 120s.
timeout = 120
keepalive = 2

# ── Security ───────────────────────────────────────────────────────────────────
# Limit request line and header sizes to prevent HTTP smuggling / DoS.
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# ── Logging ────────────────────────────────────────────────────────────────────
accesslog = "-"       # stdout → forwarded to systemd/journal
errorlog  = "-"
loglevel  = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" %(D)sµs'

# ── Process ────────────────────────────────────────────────────────────────────
proc_name = "cyberlsonlog-ai"
preload_app = True    # Load app before forking; catches import errors early
