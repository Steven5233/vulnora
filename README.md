
# Vulnora

[![License](https://img.shields.io/github/license/Steven5233/vulnora)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](backend/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-brightgreen)](backend/requirements.txt)
[![Celery](https://img.shields.io/badge/Celery-5.4+-orange)](backend/requirements.txt)
![GitHub stars](https://img.shields.io/github/stars/Steven5233/vulnora?style=social)

**An open-source vulnerability management platform that bridges technical security findings with global compliance frameworks (NIST, ISO 27001, GDPR, PCI DSS) and now includes a powerful real-time Business Logic Flaws scanner for serious bug bounty hunting.**

A modern full-stack penetration testing and vulnerability management platform that performs **real vulnerability scanning** using industry-standard tools and automatically maps findings to major compliance standards.

---

## ✨ Key Features

- **Real scanning engine** with industry tools:
  - **Nuclei** — CVEs, vulnerabilities & misconfigurations
  - **Subfinder** — subdomain enumeration
  - **Nmap** — port & service discovery
  - **httpx** — tech detection & headers
  - **Feroxbuster** — fast directory brute-forcing
  - **Logic Flaws Scanner** — **Advanced** business logic vulnerability detection with real HTTP requests

- High-performance **parallel scanning** using `ThreadPoolExecutor`
- Reliable **background processing** with **Celery + Redis** (queued tasks, retries, progress tracking)
- **Live per-module progress** via polling
- **Selective Logic Flaw Testing** — Choose specific logic checks or run all
- Professional **PDF reports** with risk scoring, detailed PoCs for every logic flaw, and automated compliance mapping
- Asset inventory with strict ownership enforcement
- Role-based access control (RBAC)
- Strong input validation & security hardening
- Dark cyber-themed Streamlit frontend with real-time updates
- Export options: JSON findings and PDF reports

**Compliance Frameworks Supported**  
ISO 27001 • NIST CSF • GDPR • PCI DSS • SOC 2 • CIS Controls

### Advanced Business Logic Flaws Module (Most Hunters Miss These)

The enhanced `logic_flaws` module performs **real HTTP requests** to detect high-impact business logic issues that traditional scanners completely miss. It now includes 12 powerful checks:

**Core Checks:**
- Client-side trust / Price & Quantity Manipulation
- IDOR / Broken Object Level Authorization (BOLA)
- Broken Function Level Authorization (BFLA / Privilege Escalation)
- Workflow & State Machine Bypass
- Race Conditions
- Price, Discount & Refund Abuse
- Multi-Account Manipulation (cross-user attacks via session/cookie)

**New Powerful Checks:**
- **Mass Assignment** — Injecting privileged fields (role, balance, is_admin, etc.)
- **HTTP Parameter Pollution (HPP)** — Duplicate or malformed parameters to bypass filters
- **Forced State Transition** — Jumping straight to “paid/completed” states
- **Coupon / Discount Stacking Abuse**
- **Balance Manipulation / Refund Loop** — Creating negative balances or exploiting refunds

All checks return **detailed Proof-of-Concept (PoC)** payloads that appear directly in the results **and** the generated PDF report.

---

## 🚀 Quick Start (Docker Recommended)

```bash
git clone https://github.com/Steven5233/vulnora.git
cd vulnora

# Copy and configure environment
cp backend/.env.example backend/.env
# Edit backend/.env and set a strong SECRET_KEY
```

Start all services:

```bash
docker compose up --build -d
```

**Access points:**
- **Frontend (Streamlit)** → http://localhost:8501
- **Backend API** → http://localhost:8000
- **Flower (Celery monitoring)** → http://localhost:5555 (optional)

To stop:

```bash
docker compose down
```

---

## Manual Setup (Advanced)

### Install Tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

sudo apt install -y nmap feroxbuster
nuclei -update-templates
```

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd ../frontend
pip install streamlit requests pandas
streamlit run app.py --server.port 8501
```

### Celery Worker (separate terminal)

```bash
cd backend
celery -A app.celery_app worker --loglevel=info --concurrency=4
```

---

## How to Use

1. Register / Login (RBAC enforced)
2. Add **Assets** (targets you own or have explicit permission to test)
3. Go to **Launch Scan**
4. Select modules (including `logic_flaws`)
5. If `logic_flaws` is selected, choose specific checks or leave empty to run **all**
6. Monitor **live progress**
7. View results — Technical findings + **Business Logic Flaws** with full PoCs
8. Download professional **PDF report** (now fully includes all logic findings with PoCs and compliance mapping)

---

## New: Logic Flaws Detection

The `logic_flaws` module performs **real HTTP requests** to detect business logic issues that automated scanners usually miss. It supports:
- Full logic scan (all 12 checks)
- Selective testing (e.g., only Mass Assignment + Forced State Transition)
- Safe rate-limited checks with detailed PoCs that appear in the PDF report

**Important**: Use only on authorized targets. Logic flaw testing can trigger unexpected behavior.

---

## Architecture

- **Backend**: FastAPI + SQLAlchemy + JWT + Celery + Redis
- **Scanning**: Parallel execution with timeouts
- **Logic Scanner**: Async `httpx` with real request testing
- **Frontend**: Streamlit with dark cyber theme + real-time polling
- **Reports**: Enhanced FPDF with full logic flaw section
- **Deployment**: Docker Compose (Redis + dedicated Celery worker)

---

## Project Structure

```bash
vulnora/
├── backend/
│   ├── app/
│   │   ├── logic_scanner.py      # Expanded: 12 business logic checks
│   │   ├── routers/scans.py      # Scan endpoints + logic integration
│   │   ├── constants.py          # Compliance map & tool config
│   │   ├── schemas.py            # Updated with selected_logic_checks
│   │   ├── main.py
│   │   └── report.py             # Enhanced PDF with full logic findings
├── frontend/
│   └── app.py                    # Updated with logic flaw UI
├── docker-compose.yml
├── LICENSE
├── SECURITY.md
└── README.md
```

---

## About the Author

Vulnora is built by **Steven** (séç gúy), a cybersecurity researcher and ethical hacker focused on penetration testing, bug bounty hunting, and compliance.

The goal is to provide a powerful, free tool that combines traditional scanning with **business logic flaw detection** — something rarely found in open-source platforms.

Contributions and responsible feedback are welcome.

---

## Roadmap

- OWASP ZAP integration
- AI-powered summary for logic flaws
- Authenticated logic scanning (cookies/JWT support)
- Historical trending dashboard
- Scheduled scans
- Team/organization support

---

## Legal & Ethical Notice

**Vulnora is intended solely for ethical hacking, authorized penetration testing, bug bounty hunting (within scope), security research, and compliance activities** on systems you own or have **explicit written permission** to test.

Unauthorized scanning is illegal. Always respect program scopes and legal boundaries.

**Stay ethical. Scan responsibly.**

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

If Vulnora helps you in your bug bounty journey or security work, please star ⭐ the repository!

---

**Made with passion for the cybersecurity and bug bounty community.**
```
