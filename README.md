
# Vulnora

[![License](https://img.shields.io/github/license/Steven5233/vulnora)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12+-blue)](backend/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-brightgreen)](backend/requirements.txt)
[![Celery](https://img.shields.io/badge/Celery-5.4+-orange)](backend/requirements.txt)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.38+-FF4B4B)](frontend/app.py)
![GitHub stars](https://img.shields.io/github/stars/Steven5233/vulnora?style=social)

**Vulnora** is a **professional-grade, open-source hybrid vulnerability scanning and manual pentesting platform** that combines powerful automated DAST scanning with full interactive manual testing capabilities.

It bridges **real-world security findings** (Nuclei, OWASP ZAP, custom logic flaws) with **global compliance frameworks** (NIST CSF, ISO 27001, GDPR, PCI DSS, SOC 2) while providing a complete Burp Suite-like experience through integrated **ZAP Proxy + Repeater**.

Built for ethical hackers, bug bounty hunters, penetration testers, and GRC professionals who need **both automation and manual depth**.

---

## ✨ Key Features

### Automated Scanning Engine
- **Nuclei** – CVEs, misconfigurations, exposures
- **OWASP ZAP** – Full Spider + Active Scan (NEW)
- **Subfinder + Nmap + httpx + Feroxbuster** – Recon & discovery
- **Logic Flaws Scanner** – 12 real business logic vulnerabilities with HTTP requests

### Authenticated Logic Scanning (NEW)
- Full support for **Cookies** and **JWT** authentication
- Multi-account manipulation, IDOR/BOLA, privilege escalation, and more — now works against authenticated targets

### Manual Pentesting Suite (NEW)
- **ZAP Proxy** – Live traffic interception (browser proxy: `http://localhost:8090`)
- **ZAP Repeater** – Edit and resend any request (full request/response editor)
- Breakpoints, session management, JWT/cookie injection
- Sites tree, HTTP history, and root CA for HTTPS

### Professional Platform Features
- Parallel scanning with Celery + Redis (background jobs, retries, live progress)
- Selective module & logic flaw testing
- Asset inventory + strict RBAC
- Professional **PDF reports** with PoCs, risk scores, and compliance mapping
- Dark cyber-themed Streamlit UI with real-time updates
- Export: JSON + PDF

**Compliance Frameworks Supported**  
ISO 27001 • NIST CSF • GDPR • PCI DSS • SOC 2 • CIS Controls

---

## 🚀 Quick Start (Docker Recommended – Updated for ZAP + Proxy)

```bash
git clone https://github.com/Steven5233/vulnora.git
cd vulnora

# Copy environment file
cp backend/.env.example backend/.env
# Edit backend/.env and set a strong SECRET_KEY
```

Start the full stack:

```bash
docker compose up --build -d
```

**Access points:**
- **Frontend (Streamlit)** → http://localhost:8501
- **Backend API** → http://localhost:8000
- **ZAP Proxy** → `http://localhost:8090` (set in your browser)
- **ZAP Root CA** (for HTTPS) → http://localhost:8080/OTHER/core/other/rootcert/
- **Celery Flower (optional monitoring)** → http://localhost:5555

To stop:

```bash
docker compose down
```

---

## How to Use

### Automated Scans
1. Register / Login
2. Add **Assets** (targets you own or have permission to test)
3. Go to **Launch Scan**
4. Select modules (`nuclei`, `zap`, `logic_flaws`, etc.)
5. For `logic_flaws`: choose specific checks + provide **Cookies (JSON)** or **JWT**
6. Click **Start Full Scan** → watch live progress
7. View results + download professional PDF report

### Manual Pentesting (Proxy + Repeater)
1. Open **Proxy Dashboard** in Vulnora
2. Set your browser proxy to `http://localhost:8090`
3. (Optional) Install ZAP Root CA for HTTPS decryption
4. Browse your target → see live **Sites** and **HTTP History**
5. Go to **Repeater**
6. Load any request from history, edit headers/body/cookies/JWT, and **Send**
7. Use breakpoints for on-the-fly interception

**Perfect for deep manual testing after automated discovery.**

---

## Advanced Business Logic Flaws Module

Performs **real HTTP requests** to detect issues traditional scanners miss. Now fully supports authenticated sessions.

**12 Checks Included:**
- Client-side trust / Price & Quantity Manipulation
- IDOR / Broken Object Level Authorization (BOLA)
- Broken Function Level Authorization (BFLA)
- Workflow & State Machine Bypass
- Race Conditions
- Price, Discount & Refund Abuse
- **Multi-Account Manipulation** (cross-user attacks)
- Mass Assignment / Object Injection
- HTTP Parameter Pollution (HPP)
- Forced State Transition
- Coupon / Discount Stacking Abuse
- Balance Manipulation / Refund Loop

Each check returns detailed PoCs that appear in the UI **and** PDF report.

---

## Architecture

- **Backend**: FastAPI + SQLAlchemy + JWT Auth + Celery + Redis
- **Scanning Engine**: Parallel `ThreadPoolExecutor` + custom async logic scanner
- **OWASP ZAP**: Integrated via REST API (Spider + Active Scan + Proxy + Repeater)
- **Frontend**: Streamlit with dark cyber theme + real-time polling
- **Reports**: Enhanced FPDF with full logic flaws, ZAP findings, and compliance mapping
- **Deployment**: Docker Compose (includes dedicated ZAP container with Proxy port 8090)

---

## Project Structure (Key Updated Files)

```bash
vulnora/
├── backend/
│   ├── app/
│   │   ├── logic_scanner.py          # 12 checks + cookies/JWT auth
│   │   ├── routers/
│   │   │   ├── scans.py              # Full scan orchestration + ZAP
│   │   │   └── zap.py                # NEW: Proxy + Repeater API
│   │   ├── constants.py
│   │   ├── schemas.py                # Updated with auth_info
│   │   ├── models.py                 # Scan model with auth_info
│   │   └── main.py                   # Includes new ZAP router
│   └── celery_app.py
├── frontend/
│   └── app.py                        # NEW Proxy Dashboard + Repeater pages
├── docker-compose.yml                # Updated ZAP service (ports 8080 + 8090)
├── LICENSE
└── README.md
```

---

## About the Author

Vulnora is built by **Adoyi Steven** (séç gúy), a cybersecurity researcher and penetration tester focused on building practical tools for ethical hacking, bug bounty hunting, and enterprise GRC.

The goal: create a **free, powerful, and complete** platform that combines automated scanning with professional manual testing capabilities.

---

## Roadmap (Updated)

- ✅ **OWASP ZAP integration** (Spider + Active Scan)
- ✅ **Authenticated logic scanning** (Cookies + JWT)
- ✅ **Proxy + Repeater** (full manual interception & request editing)
- 🔄 AI-powered summary for logic flaws
- 🔄 Historical trending dashboard
- 🔄 Scheduled scans
- 🔄 Team / organization support

---

## Legal & Ethical Notice

**Vulnora is intended solely for ethical hacking, authorized penetration testing, bug bounty programs (within scope), security research, and compliance activities** on systems you own or have **explicit written permission** to test.

Unauthorized scanning is illegal. Always respect program rules and legal boundaries.

**Stay ethical. Scan responsibly.**

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

If Vulnora helps you find critical bugs or pass compliance audits, please star ⭐ the repository and consider contributing!

---

**Made with passion for the cybersecurity, bug bounty, and GRC community.**

Built to be the **go-to open-source tool** for modern vulnerability management and manual pentesting.
```
