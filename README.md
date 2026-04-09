# Vulnora

[![License](https://img.shields.io/github/license/Steven5233/vulnora)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](backend/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-brightgreen)](backend/requirements.txt)
[![Celery](https://img.shields.io/badge/Celery-5.4+-orange)](backend/requirements.txt)
![GitHub stars](https://img.shields.io/github/stars/Steven5233/vulnora?style=social)

**An open-source vulnerability management platform that bridges technical security findings with global compliance frameworks (NIST, ISO 27001, GDPR, PCI DSS).**

A modern full-stack penetration testing and vulnerability management platform that performs **real vulnerability scanning** using industry-standard tools and automatically maps findings to major compliance standards.

---

## ✨ Key Features

- **Real scanning engine** with industry tools:
  - **Nuclei** — CVEs, vulnerabilities & misconfigurations
  - **Subfinder** — subdomain enumeration
  - **Nmap** — port & service discovery (structured parsing)
  - **httpx** — tech detection & headers
  - **Feroxbuster** — fast directory brute-forcing
- **High-performance parallel scanning** using `ThreadPoolExecutor`
- **Reliable background processing** with **Celery + Redis** (queued tasks, retries, progress tracking)
- **Live per-module progress** (subdomains, nuclei, directories, etc.) via polling
- Professional **PDF reports** with risk scoring and automated compliance mapping
- Asset inventory with strict ownership enforcement
- Role-based access control (RBAC)
- Strong input validation & security hardening (prevents command injection)
- Dark cyber-themed Streamlit frontend with real-time updates
- Export options: scan history (CSV) and findings (JSON)

**Compliance Frameworks Supported**  
ISO 27001 • NIST CSF • GDPR • PCI DSS • SOC 2 • CIS Controls

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
2. Add **Assets** you own or have permission to test
3. Launch a scan → choose target and modules
4. Monitor **live progress** (per-module updates)
5. View structured results with severity and CVSS scores
6. Download professional **PDF report** with compliance insights
7. Export data for audits or integration

---

## Architecture & Recent Improvements

- **Backend**: FastAPI + SQLAlchemy + JWT authentication + Celery
- **Scanning**: Parallel execution with timeouts and structured data
- **Background Tasks**: Celery + Redis (reliable queuing and retries)
- **Frontend**: Streamlit dark theme with real-time polling
- **Reports**: FPDF with global compliance mapping
- **Deployment**: Docker Compose (Redis + dedicated Celery worker)

**Key Recent Enhancements**:
- Migrated to Celery + Redis background worker
- Added live per-module progress tracking
- Parallelized scanning modules
- Integrated Feroxbuster for directories
- Improved Nmap parsing and risk scoring
- Better error handling and timeouts

---

## Project Structure

```bash
vulnora/
├── backend/                  # FastAPI + Celery + scanning logic
│   ├── app/
│   │   ├── celery_app.py     # Celery configuration
│   │   ├── routers/scans.py  # Scan API and logic
│   │   ├── constants.py      # Compliance map & tool config
│   │   └── report.py         # PDF generation
├── frontend/                 # Streamlit UI
├── docker-compose.yml        # Redis + Celery worker
├── LICENSE
├── SECURITY.md
├── README.md
```

---

## About the Author

Vulnora is built by **Steven** (séç gúy), a cybersecurity researcher and ethical hacker with experience in penetration testing and compliance auditing.

The primary goal is to make professional-grade vulnerability scanning and compliance reporting accessible to individuals, small teams, and organizations without relying on expensive commercial tools.

Contributions, feedback, and responsible security reports are always welcome.

---

## Roadmap

- OWASP ZAP integration for active DAST scanning
- Historical trending and compliance dashboard
- Team / organization support with shared assets
- AI-powered executive summary in PDF reports
- Scheduled / recurring scans
- Export to DefectDojo / Dradis

---

## Legal & Ethical Notice

**Vulnora is intended solely for ethical hacking, authorized penetration testing, security research, and compliance activities** on systems you own or have explicit written permission to test.

Unauthorized scanning of any system is illegal. Use responsibly and ethically.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

If Vulnora helps your work or research, please star⭐ the repository — it helps others discover the project!

---

**Stay ethical. Scan responsibly.**

Made with passion for the cybersecurity community.
