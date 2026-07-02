# CyberlsonLog AI – Deployment Guide

---

## Table of Contents

1. [Local Development](#1-local-development)
2. [Virtual Environment Setup](#2-virtual-environment-setup)
3. [Configuration](#3-configuration)
4. [VPS Deployment (Ubuntu 22.04)](#4-vps-deployment-ubuntu-2204)
5. [Gunicorn Setup](#5-gunicorn-setup)
6. [Nginx Configuration](#6-nginx-configuration)
7. [HTTPS with Let's Encrypt](#7-https-with-lets-encrypt)
8. [Systemd Service](#8-systemd-service)
9. [Render Deployment](#9-render-deployment)
10. [Security Checklist](#10-security-checklist)

---

## 1. Local Development

```bash
# Clone the repository
git clone https://github.com/cYBerLson/CyberlsonLog-AI.git
cd CyberlsonLog-AI

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/Mac
# venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env
# Edit .env and set a strong SECRET_KEY

# Run development server
python run.py
# Visit http://127.0.0.1:5000
```

---

## 2. Virtual Environment Setup

Always use a virtual environment to isolate project dependencies.

```bash
# Create
python3.11 -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Verify Python version
python --version  # Should show Python 3.11+

# Install all dependencies
pip install -r requirements.txt

# Deactivate when done
deactivate
```

---

## 3. Configuration

CyberlsonLog AI is configured entirely through environment variables (12-factor app pattern). No secrets are hardcoded.

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask session signing key (min 32 random chars) | **Yes** |
| `FLASK_ENV` | `development` or `production` | Yes |
| `FLASK_DEBUG` | `false` in production | Yes |
| `PORT` | Server port (default: 5000) | No |
| `GUNICORN_WORKERS` | Number of worker processes | No |

Generate a strong secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 4. VPS Deployment (Ubuntu 22.04)

### 4.1 Server Setup

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python 3.11 and dependencies
sudo apt install -y python3.11 python3.11-venv python3-pip nginx certbot python3-certbot-nginx git

# Create a dedicated system user (principle of least privilege)
# Never run the application as root
sudo useradd --system --home /opt/cyberlsonlog ai --shell /bin/bash cyberlsonlog ai
sudo mkdir -p /opt/cyberlsonlog-ai
sudo chown cyberlsonlog-ai:cyberlsonlog-ai /opt/cyberlsonlog-ai
```

### 4.2 Application Deployment

```bash
# Switch to the application user
sudo -u cyberlsonlog-ai -i

# Clone repository
cd /opt/cyberlsonlog-ai
git clone https://github.com/cYBerLson/CyberlsonLog-Ai.git

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create uploads and reports directories
mkdir -p uploads reports

# Set up environment variables
cp .env.example .env
# Edit .env with production values:
nano .env
```

### 4.3 Directory Permissions

```bash
# Restrict uploads directory: only the app user can read/write
chmod 700 /opt/cyberlsonlog-ai/uploads
chmod 700 /opt/cyberlsonlog-ai/reports

# Static files: readable by Nginx
chmod -R 755 /opt/cyberlsonlog-ai/static
```

---

## 5. Gunicorn Setup

### Test Gunicorn manually first:

```bash
cd /opt/cyberlsonlog-ai
source venv/bin/activate

gunicorn --config gunicorn.conf.py run:application
# Should output: [INFO] Listening at: http://127.0.0.1:5000
# Press Ctrl+C to stop
```

---

## 6. Nginx Configuration

Create the Nginx site configuration:

```bash
sudo nano /etc/nginx/sites-available/cyberlsonlogai
```

Pasting the following:

```nginx
# /etc/nginx/sites-available/cyberlsonlogai
# ========================================
# Nginx reverse proxy for CyberlsonLog-AI
# Security hardening per OWASP guidelines

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Redirect all HTTP to HTTPS (configured after Certbot)
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # ── SSL (managed by Certbot) ────────────────────────────────────────────
    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # ── Security Headers ────────────────────────────────────────────────────
    # These complement the application-level headers set by Flask.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # ── Request Size Limit ──────────────────────────────────────────────────
    # Must match Flask's MAX_CONTENT_LENGTH (10 MB)
    client_max_body_size 11m;

    # ── Rate Limiting ───────────────────────────────────────────────────────
    # Prevent DoS via upload endpoint
    limit_req_zone $binary_remote_addr zone=upload:10m rate=5r/m;

    # ── Proxy to Gunicorn ───────────────────────────────────────────────────
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    # Apply rate limiting only to the upload endpoint
    location /analyze {
        limit_req zone=upload burst=3 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }

    # ── Static Files ────────────────────────────────────────────────────────
    # Serve static assets directly via Nginx (faster than Gunicorn)
    location /static {
        alias /opt/cyberlsonlog-ai/static;
        expires 1d;
        add_header Cache-Control "public";
    }

    # ── Deny access to sensitive files ──────────────────────────────────────
    location ~ /\. {
        deny all;
        return 404;
    }

    location ~ \.(env|py|log|txt|sql)$ {
        deny all;
        return 404;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/cyberlsonlog-ai /etc/nginx/sites-enabled/
sudo nginx -t                    # Test configuration
sudo systemctl reload nginx
```

---

## 7. HTTPS with Let's Encrypt

```bash
# Install Certbot (if not already installed)
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate
# Replace yourdomain.com with your actual domain
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Certbot auto-renews via systemd timer — verify:
sudo systemctl status certbot.timer

# Test auto-renewal
sudo certbot renew --dry-run
```

---

## 8. Systemd Service

Create a systemd unit for automatic startup and process supervision:

```bash
sudo nano /etc/systemd/system/cyberlsonlog-ai.service
```

```ini
[Unit]
Description=CyberlsonLog AI – Intelligent Log Anomaly Detection
After=network.target
Wants=network.target

[Service]
# Run as dedicated non-root user
User=cyberlsonlog
Group=cyberlsonlog
WorkingDirectory=/opt/cyberlsonlog-ai

# Load environment variables from .env file
EnvironmentFile=/opt/cyberlsonlog ai/.env

# Gunicorn start command
ExecStart=/opt/cyberlsonlog-ai/venv/bin/gunicorn --config gunicorn.conf.py run:application

# Restart on failure
Restart=always
RestartSec=5

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/cyberlsonlog-ai/uploads /opt/cyberlsonlog-ai/reports
NoNewPrivileges=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberlsonlog ai

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cyberlsonlson-ai
sudo systemctl start cyberlsonlog-ai
sudo systemctl status cyberlsonlog-ai

# View logs
sudo journalctl -u cyberlsonlog-ai -f
```

---

## 9. Render Deployment

### render.yaml

Create `render.yaml` in the project root:

```yaml
services:
  - type: web
    name: cyberlsonlog-ai
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn --config gunicorn.conf.py run:application
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: FLASK_ENV
        value: production
      - key: FLASK_DEBUG
        value: false
      - key: PORT
        value: 10000
    healthCheckPath: /health
    autoDeploy: true
    plan: starter
```

### Steps:
1. Push project to GitHub
2. Create account at [render.com](https://render.com)
3. New Web Service → Connect GitHub repo
4. Render auto-detects `render.yaml`
5. Set `SECRET_KEY` in Environment tab
6. Deploy

### Railway:
```bash
railway login
railway init
railway add
railway up
# Set env vars in Railway dashboard
```

---

## 10. Security Checklist

Before going live, verify:

- [ ] `FLASK_DEBUG=false` in production
- [ ] `SECRET_KEY` is a random 32+ character string
- [ ] Application runs as non-root user
- [ ] HTTPS enabled (Certbot)
- [ ] Nginx rate limiting active
- [ ] `uploads/` directory has 700 permissions
- [ ] `.env` is in `.gitignore`
- [ ] `uploads/` and `reports/` are in `.gitignore`
- [ ] Nginx serves static files directly
- [ ] Nginx blocks access to `.env`, `.py`, `.log` files
- [ ] systemd `NoNewPrivileges=true` set
- [ ] `certbot renew --dry-run` succeeds
- [ ] Firewall allows only ports 80, 443, and your SSH port
  ```bash
  sudo ufw allow 22/tcp
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp
  sudo ufw enable
  ```
