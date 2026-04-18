
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

## 🐧 Alternative: Manual Installation on Kali Linux

Vulnora can be installed and run natively on **Kali Linux** without Docker. This is useful for users who prefer full control, easier debugging, or running on bare-metal Kali.

### Prerequisites

Make sure you have the following installed:

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    redis-server \
    git curl wget
```

**Install OWASP ZAP** (required for Proxy + Repeater):

```bash
sudo apt install -y zaproxy
# Or download the latest from https://www.zaproxy.org/download/
```

### Step-by-Step Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/Steven5233/vulnora.git
   cd vulnora
   ```

2. **Set up the backend environment**

   ```bash
   cd backend

   # Create and activate virtual environment
   python3 -m venv venv
   source venv/bin/activate

   # Install Python dependencies
   pip install -r requirements.txt

   # Configure environment
   cp .env.example .env
   ```

   **Edit `backend/.env`** and set a strong `SECRET_KEY`:

   ```env
   SECRET_KEY=your-super-strong-random-secret-key-here
   # You can generate one with: openssl rand -hex 32
   ```

   (Optional) Adjust other variables like `DATABASE_URL` if you want to use PostgreSQL instead of SQLite.

3. **Start supporting services**

   - **Redis** (required for Celery):

     ```bash
     sudo systemctl start redis-server
     sudo systemctl enable redis-server   # optional: auto-start on boot
     ```

   - **OWASP ZAP** (in daemon/headless mode for Proxy):

     Open a new terminal and run:

     ```bash
     zap.sh -daemon -port 8090 -config api.disablekey=true -config proxy.port=8090
     ```

     ZAP will listen on `http://localhost:8090`.

4. **Start the Backend (FastAPI)**

   In the `backend/` directory (with venv activated):

   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

   The API will be available at `http://localhost:8000`.

5. **Start Celery Worker**

   Open another terminal, navigate to `backend/`, activate the venv, and run:

   ```bash
   celery -A celery_app worker --loglevel=info
   ```

   (Optional) Start Celery Beat if scheduled tasks are added later:

   ```bash
   celery -A celery_app beat --loglevel=info
   ```

6. **Start the Frontend (Streamlit)**

   Open yet another terminal:

   ```bash
   cd ../frontend
   streamlit run app.py --server.port 8501 --server.address 0.0.0.0
   ```

### Access Points (Manual Setup)

- **Frontend (UI)**: http://localhost:8501
- **Backend API**: http://localhost:8000
- **ZAP Proxy**: http://localhost:8090 (configure your browser to use this proxy)
- **ZAP Root CA** (for HTTPS decryption): Visit `http://localhost:8080/OTHER/core/other/rootcert/` in ZAP-enabled browser and import the certificate

### Useful Commands

- **Stop services**: Use `Ctrl + C` in each terminal, or `sudo systemctl stop redis-server`
- **View logs**: Check terminal outputs or add `--loglevel=debug` for more details
- **Rebuild dependencies**: `pip install -r requirements.txt --upgrade`

### Notes & Troubleshooting

- Make sure Redis is running before starting Celery.
- For production-like use on Kali, consider using `tmux` or `screen` to manage multiple terminals.
- If you encounter port conflicts, change ports in ZAP (`-port 8090`), uvicorn (`--port 8000`), or Streamlit (`--server.port 8501`).
- The advanced IDOR/BOLA scanners (`logic_scanner.py` and `idorforge_scanner.py`) require valid authentication cookies/JWT when testing — provide them through the UI.
- ZAP integration works via its REST API on port 8090.

**Docker is still the recommended and easiest way** for most users, especially for quick testing. Use the manual Kali setup when you need deeper customization or are running on a dedicated Kali machine.

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
