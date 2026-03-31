# 🛡️ Vulnora

**Real Vulnerability Scanner for Ethical Hacking & Global GRC**

A modern full-stack penetration testing platform built for ethical hackers and security professionals.

**Built by Cyber Security Researcher — séç gúy**

---

## ✨ Features

- Real vulnerability scanning using **Nuclei**, **Subfinder**, **Nmap**, and **httpx**
- Live scan progress with real-time status and progress bar
- Professional PDF reports with **global compliance mapping**
- Asset management system
- Role-based access control (Users see only their scans, Admins see everything)
- Input validation and security hardening
- Dark cyber-themed Streamlit frontend
- Export scan history as CSV and findings as JSON
- Global compliance mapping to:
  - ISO 27001
  - NIST Cybersecurity Framework (CSF)
  - GDPR
  - PCI DSS
  - SOC 2
  - CIS Controls

---

## 🚀 Tech Stack

**Backend:** FastAPI, SQLAlchemy, Pydantic v2, JWT Authentication  
**Scanning Tools:** Nuclei, Subfinder, Nmap, httpx  
**Frontend:** Streamlit (with custom cyber theme)  
**Reports:** FPDF2  
**Database:** SQLite (easily replaceable)

---

## 🛠️ Quick Start

### Prerequisites
- Python 3.12+
- Go (required for Nuclei, Subfinder, httpx)
- Nmap
- Docker (optional but recommended)

### 1. Clone the Repository
```bash
git clone https://github.com/Steven5233/vulnora.git
cd vulnora
```

### 2. Install Scanning Tools
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

sudo apt install -y nmap
nuclei -update-templates
```

### 3. Backend Setup
```bash
cd backend
cp .env.example .env
# Edit .env and set a strong SECRET_KEY

pip install -r requirements.txt
```

### 4. Run the Application

**Using Docker (Recommended):**
```bash
docker compose up --build
```

**Manually:**
```bash
# Terminal 1 - Backend
cd backend
uvicorn app.main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
streamlit run app.py --server.port 8501
```

Open **http://localhost:8501** in your browser.

---

## 📖 How to Use

1. Register or login (default: `user` / your password)
2. Add target assets (domains or you you are authorized to test)
3. Go to **Launch Scan**, select target and modules
4. Watch **Live Progress** during the scan
5. View detailed results and severity findings
6. Download professional **PDF Report** with compliance mapping
7. Export history as CSV

> **⚠️ Legal Notice**: Use only on systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 🔐 Security Features

- Strong input validation to prevent command injection
- JWT authentication + rate limiting
- Users can only access their own scan results
- Admin-only routes properly protected
- No raw shell execution

---

## 📊 Global Compliance Mapping

Vulnora automatically maps findings to major international standards, making it suitable for professional penetration testing reports and GRC requirements.

---

## 📁 Project Structure
```
vulnora/
├── backend/          # FastAPI backend
├── frontend/         # Streamlit frontend
├── docker-compose.yml
├── README.md
```

---

## 🛣️ Roadmap

- Better background task handling with Celery + Redis
- Per-module scan progress
- Team/Organization support
- Integration with more tools (ZAP, Burp, etc.)
- Vulnerability trending dashboard

---

## 📝 License

This project is intended for **educational and ethical hacking purposes only**.  
Any unauthorized use against systems without permission is strictly prohibited.

---

## 👨‍💻 Author

**Built by Cyber Security Researcher — séç gúy**

---

## ⭐ Support

If you like the project, please give it a ⭐ on GitHub!

Questions, suggestions, or contributions are welcome. Open an issue or reach out.

**Stay ethical. Scan responsibly.**

Made with ❤️ for the cybersecurity community.
```
