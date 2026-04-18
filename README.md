
# Vulnora v2.1.0

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
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

## ✨ What's New in v2.1.0

- **Advanced IDOR/BOLA & Logic Flaws Engine** — Now includes multi-account creation, cross-session manipulation, GraphQL object manipulation, bulk operations, write-only IDOR, and business logic bypasses that **90% of automated scanners and manual hunters miss**.
- Enhanced `LogicFlawScanner` with dedicated `IDORForgeProScanner`.
- Improved authenticated scanning with dynamic test account registration and session switching.
- Better discovery engine (`_smart_discovery`) for extracting real object IDs from JSON responses.
- Updated reporting with detailed PoCs for complex authorization flaws.

---

## ✨ Key Features

### Automated Scanning Engine
- **Nuclei** – CVEs, misconfigurations, exposures
- **OWASP ZAP** – Full Spider + Active Scan
- **Subfinder + Nmap + httpx + Feroxbuster** – Recon & discovery
- **Advanced Logic Flaws Scanner** – Business logic vulnerabilities with real HTTP requests and multi-account testing

### Advanced Authenticated Logic Scanning
- Full support for **Cookies**, **JWT**, and session management
- **Multi-Account Manipulation** (cross-user IDOR/BOLA)
- Dynamic test account creation for realistic privilege escalation and object access testing
- IDORForge module: numeric swapping, mass assignment, GraphQL mutations, bulk operations, and more

### Manual Pentesting Suite
- **ZAP Proxy** – Live traffic interception (browser proxy: `http://localhost:8090`)
- **ZAP Repeater** – Edit and resend any request (full request/response editor)
- Breakpoints, session management, JWT/cookie injection
- Sites tree, HTTP history, and root CA for HTTPS

### Professional Platform Features
- Parallel scanning with Celery + Redis (background jobs, retries, live progress)
- Selective module & logic flaw testing
- Asset inventory + strict RBAC
- Professional **PDF reports** with PoCs, risk scores, evidence, and compliance mapping
- Dark cyber-themed Streamlit UI with real-time updates
- Export: JSON + PDF

**Compliance Frameworks Supported**  
ISO 27001 • NIST CSF • GDPR • PCI DSS • SOC 2 • CIS Controls

---

## 🚀 Quick Start (Docker Recommended)

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
2. Add **Assets** (targets you own or have explicit permission to test)
3. Go to **Launch Scan**
4. Select modules (`nuclei`, `zap`, `logic_flaws`, `idorforge`, etc.)
5. For logic flaws: choose specific checks + provide **Cookies (JSON)** or **JWT**
6. Click **Start Full Scan** → watch live progress in real time
7. View results + download professional PDF report with full PoCs

### Manual Pentesting (Proxy + Repeater)
1. Open **Proxy Dashboard** in Vulnora
2. Configure your browser proxy to `http://localhost:8090`
3. (Optional) Install ZAP Root CA for HTTPS decryption
4. Browse your target → live **Sites** tree and **HTTP History**
5. Go to **Repeater**, load any request, edit headers/body/cookies/JWT, and **Send**
6. Use breakpoints for advanced interception

**Ideal for deep manual validation after automated discovery of complex flaws like advanced IDOR/BOLA.**

---

## Advanced Business Logic & Authorization Flaws Module

Performs **real, authenticated HTTP requests** to detect issues that traditional scanners routinely miss.

**Key Capabilities (v2.1.0):**
- IDOR / Broken Object Level Authorization (BOLA) with smart ID discovery
- **Multi-Account Manipulation** — dynamically creates test accounts and tests cross-user access/modification
- GraphQL object manipulation and mutations
- Bulk operations and write-only IDOR
- Mass assignment, workflow bypass, forced state transitions
- Privilege escalation and business logic abuse (price, balance, coupon, etc.)

Each finding includes detailed evidence, similarity scores, and ready-to-use PoCs.

---

## Architecture

- **Backend**: FastAPI + SQLAlchemy + JWT Auth + Celery + Redis
- **Scanning Engine**: `LogicFlawScanner` + `IDORForgeProScanner` with async discovery and multi-session testing
- **OWASP ZAP**: Integrated via REST API (Spider + Active Scan + Proxy + Repeater)
- **Frontend**: Streamlit with dark cyber theme + real-time polling
- **Reports**: Enhanced FPDF with logic flaws, ZAP findings, and compliance mapping
- **Deployment**: Docker Compose (includes dedicated ZAP container)

---

## Project Structure (Key Files)

```bash
vulnora/
├── backend/
│   ├── app/
│   │   ├── logic_scanner.py          # Core multi-account IDOR/BOLA logic
│   │   ├── idorforge_scanner.py      # Advanced IDORForgeProScanner
│   │   ├── routers/
│   │   │   ├── scans.py              # Scan orchestration
│   │   │   └── zap.py                # Proxy + Repeater API
│   │   ├── constants.py
│   │   ├── schemas.py
│   │   ├── models.py
│   │   └── main.py
│   └── celery_app.py
├── frontend/
│   └── app.py
├── docker-compose.yml
├── LICENSE
└── README.md
```

---

## About the Author

Vulnora is built by **Adoyi Steven(séç gúy)**, a cybersecurity researcher and penetration tester focused on practical tools for ethical hacking, bug bounty hunting, and enterprise GRC.

---

## Roadmap

- AI-powered summary and remediation suggestions for logic flaws
- Historical trending dashboard
- Scheduled scans
- Team / organization support
- Further enhancements to authorization flaw detection

---

## Legal & Ethical Notice

**Vulnora is intended solely for ethical hacking, authorized penetration testing, bug bounty programs (within scope), security research, and compliance activities** on systems you own or have **explicit written permission** to test.

Unauthorized scanning is illegal. Always respect program rules and legal boundaries.

**Stay ethical. Scan responsibly.**

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see the [LICENSE](LICENSE) file for details.

The AGPL-3.0 ensures that any modifications or derivative works, especially when offered as a network service, must also be open-sourced under the same license.

If Vulnora helps you discover critical authorization flaws or pass compliance audits, please star the repository ⭐ and consider contributing back to the community!

---

**Made with passion for the cybersecurity, bug bounty, and GRC community.**

Vulnora — The open-source platform that catches what others miss.
```
