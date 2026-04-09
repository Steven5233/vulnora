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

```bash
git clone https://github.com/Steven5233/vulnora.git
cd vulnora

cp backend/.env.example backend/.env   # Edit and set a strong SECRET_KEY
docker compose up --build -d
```

**Access:**
- Frontend (Streamlit): http://localhost:8501
- Backend API: http://localhost:8000
- Flower (task monitor): http://localhost:5555 (optional)

---

## Manual Setup (Advanced)

(See the previous version for full manual steps — they remain unchanged.)

## How to Use

(See the previous version for the step-by-step guide — unchanged.)

## Architecture & Recent Improvements

(See the previous version — unchanged.)

## Project Structure

(See the previous version — unchanged.)

## About the Author

Vulnora is built by **Steven** (séç gúy), a cybersecurity researcher and ethical hacker with experience in penetration testing and compliance auditing.

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

Vulnora is intended **only for authorized penetration testing, security research, and compliance activities** on systems you own or have explicit permission to test.

Unauthorized scanning is illegal. Use responsibly.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

If Vulnora helps your work, please ⭐ the repo — it helps others discover it!

---

**Stay ethical. Scan responsibly.**

Made with passion for the cybersecurity community.
```
