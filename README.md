# Vulnora

[![License](https://img.shields.io/github/license/Steven5233/vulnora)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](backend/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-brightgreen)](backend/requirements.txt)
![GitHub stars](https://img.shields.io/github/stars/Steven5233/vulnora?style=social)

**An open-source vulnerability management platform that bridges technical security findings with global compliance frameworks (NIST, ISO 27001, GDPR, PCI DSS).**

A modern full-stack penetration testing and vulnerability management platform that performs **real vulnerability scanning** using industry-standard tools (Nuclei, Nmap, Subfinder, httpx, feroxbuster) and generates professional PDF reports with automated compliance mapping.

---

## ✨ Key Features

- **Real scanning engine** powered by:
  - **Nuclei** (CVEs, vulnerabilities, misconfigurations)
  - **Subfinder** (subdomain enumeration)
  - **Nmap** (port & service discovery with structured parsing)
  - **httpx** (tech detection & headers)
  - **Feroxbuster** (directory brute-forcing)
- **High-performance parallel scanning** using `ThreadPoolExecutor`
- **Reliable background worker** with **Celery + Redis** (queued, running, retry support, task monitoring)
- **Live per-module progress tracking** (subdomains, nuclei, directories, etc.)
- Professional **PDF reports** with risk scoring and **global compliance mapping**
- Asset inventory management with strict ownership enforcement
- Role-based access control (RBAC) – users see only their assets and scans
- Strong input validation and security hardening (no command injection)
- Dark cyber-themed Streamlit frontend with real-time polling
- Export scan history (CSV) and findings (JSON)
- Compliance mapping to major frameworks:
  - ISO 27001
  - NIST Cybersecurity Framework (CSF)
  - GDPR
  - PCI DSS
  - SOC 2
  - CIS Controls

---

## 🚀 Quick Start with Docker (Recommended)

The easiest way to run Vulnora is using **Docker Compose** — includes Redis and a dedicated Celery worker.

### Prerequisites

- Docker and Docker Compose
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/Steven5233/vulnora.git
cd vulnora
```

### 2. Create the `.env` file

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and set a **strong SECRET_KEY**:

```env
SECRET_KEY=your-super-long-random-secret-key-here-1234567890
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
DATABASE_URL=sqlite:///./data/vulnora.db
REDIS_URL=redis://redis:6379/0
```

### 3. Start Vulnora

```bash
docker compose up --build -d
```

**Services:**
- **Frontend (Streamlit)**: http://localhost:8501
- **Backend API**: http://localhost:8000
- **Celery Worker**: Background scan processing
- **Redis**: Task queue & result backend
- **Flower (optional)**: Task monitoring UI at http://localhost:5555

To stop:

```bash
docker compose down
```

---

## Manual Setup (Advanced)

### 1. Install Scanning Tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

sudo apt install -y nmap feroxbuster
nuclei -update-templates
```

### 2. Backend Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend Setup

```bash
cd ../frontend
pip install streamlit requests pandas
streamlit run app.py --server.port 8501
```

### 4. Start Celery Worker (in a separate terminal)

```bash
cd backend
celery -A app.celery_app worker --loglevel=info --concurrency=4
```

---

## How to Use

1. Register / Login (RBAC enforced)
2. Add authorized **Assets** (domains or IPs you own or have explicit permission to test)
3. Go to **Launch Scan** → select target and modules
4. Monitor **Live Progress** (per-module status updates via polling)
5. View results with severity, CVSS scores, and structured findings
6. Download **professional PDF report** with compliance mapping and executive-level insights
7. Export data for audits or ticketing systems

---

## Architecture & Recent Improvements

- **Backend**: FastAPI + SQLAlchemy + JWT auth + Celery
- **Scanning Engine**: Parallel execution with timeouts and structured output parsing
- **Background Tasks**: Celery + Redis (replaces simple threading) – reliable queuing, retries, and monitoring
- **Frontend**: Streamlit with dark cyber theme and real-time progress polling
- **Reports**: FPDF with compliance mapping to global standards
- **Deployment**: Docker Compose with dedicated Celery worker and Redis

**Recent Major Enhancements:**
- Switched to Celery + Redis for robust background scan management
- Added per-module live progress tracking
- Parallelized scanning modules for faster execution
- Integrated feroxbuster for directory enumeration
- Improved Nmap output with structured port/service data
- Better error handling, timeouts, and risk scoring

---

## Project Structure

```bash
vulnora/
├── backend/              # FastAPI + Celery tasks + scanning logic
│   ├── app/
│   │   ├── celery_app.py     # Celery configuration
│   │   ├── routers/scans.py  # Main scan logic & API
│   │   ├── constants.py      # Shared configs & compliance map
│   │   └── report.py         # PDF generation
├── frontend/             # Streamlit UI
├── docker-compose.yml    # Includes redis + celery-worker
├── README.md
```

---

## About the Author

Vulnora is built by **Steven** (séç gúy), a cybersecurity researcher and ethical hacker with hands-on experience in penetration testing and compliance auditing.

The goal behind Vulnora is to bridge the gap between raw technical findings and actionable compliance reports that security teams and auditors actually need — all in a free, open-source package.

Contributions, feedback, and responsible security reports are always welcome.

---

## Roadmap (Upcoming)

- OWASP ZAP integration for active DAST scanning
- Historical trending & compliance dashboard
- Team/Organization support with shared assets
- AI-powered executive summary in PDF reports
- Scheduled/recurring scans
- Export to DefectDojo / Dradis

---

## Legal & Ethical Notice

**Vulnora is for ethical hacking, authorized penetration testing, and security research only.**

Unauthorized scanning of systems without explicit written permission is illegal. Use responsibly.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

If Vulnora helps your work, please consider giving the project a ⭐ — it helps others discover it!

---

## Support

Questions, bug reports, or feature requests → [GitHub Issues](https://github.com/Steven5233/vulnora/issues)

**Stay ethical. Scan responsibly.**

Made with passion for the cybersecurity community.
```
