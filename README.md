# 🛡️ Vulnora

**Real Vulnerability Scanner for Ethical Hacking & Global GRC**

A modern full-stack penetration testing platform that performs **real vulnerability scanning** using industry-standard tools and generates professional reports with global compliance mapping.

**Built by Cybersecurity Researcher — séç gúy**

---

## ✨ Features

- Real scanning with **Nuclei** (vulnerabilities & CVEs), **Subfinder** (subdomains), **Nmap** (ports), and **httpx** (tech & headers)
- **Live scan progress** with real-time status and progress bar
- Professional **PDF reports** including global compliance mapping
- Asset inventory management
- Role-based access control (users see only their own scans; admins see everything)
- Input validation and security hardening to prevent injection attacks
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

## 🚀 Quick Start with Docker (Recommended)

The easiest way to run Vulnora is using **Docker Compose** — everything starts with a single command.

### Prerequisites
- Docker and Docker Compose installed
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Steven5233/vulnora.git
cd vulnora
```

### 2. Create the `.env` file for the backend
```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and set a **strong SECRET_KEY** (at least 64 random characters). Example:
```
SECRET_KEY=your-super-long-random-secret-key-here-1234567890
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
DATABASE_URL=sqlite:///./data/vulnora.db
```

### 3. Start Vulnora
```bash
docker compose up --build
```

- **Frontend** will be available at: **http://localhost:8501**
- **Backend API** runs at: **http://localhost:8000** (usually not accessed directly)

To stop the application:
```bash
docker compose down
```

---

## 🛠️ Manual Setup (Without Docker)

### 1. Install Scanning Tools
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

sudo apt install -y nmap
nuclei -update-templates
```

### 2. Backend Setup
```bash
cd backend
cp .env.example .env
# Edit .env with a strong SECRET_KEY
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
cd ../frontend
pip install streamlit requests pandas
```

### 4. Run Manually (Two Terminals)

**Terminal 1 – Backend**
```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 – Frontend**
```bash
cd frontend
streamlit run app.py --server.port 8501
```

Open **http://localhost:8501** in your browser.

---

## 📖 How to Use

1. Register a new account or login (default admin credentials can be used if seeded)
2. Add target **Assets** (only domains/IPs you are authorized to test)
3. Go to **Launch Scan**, select target and scanning modules
4. Watch **Live Progress** during the scan
5. View detailed results with severity ratings
6. Download **PDF Report** containing global compliance mapping
7. Export history or findings for documentation

> **⚠️ Legal & Ethical Notice**: Use Vulnora **only** on systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 🔐 Security Features

- Strong input validation to prevent command injection
- JWT-based authentication with rate limiting
- Users can only view their own scan results (admin exception)
- No raw shell command execution
- Secure PDF report generation

---

## 📁 Project Structure
```
vulnora/
├── backend/              # FastAPI backend + real scanning logic
├── frontend/             # Streamlit UI
├── docker-compose.yml    # One-command deployment
├── backend/Dockerfile
├── frontend/Dockerfile
├── README.md
```

---

## 🛣️ Suggested Improvements & Roadmap

- [ ] Replace simple threading with **Celery + Redis** for better background scan management
- [ ] Add per-module live progress (e.g., "Running Nuclei...", "Enumerating subdomains...")
- [ ] Team / Organization support with shared assets
- [ ] Integration with additional tools (OWASP ZAP, Burp Suite export)
- [ ] Automated daily Nuclei template updates via cron
- [ ] Vulnerability trending and historical comparison dashboard
- [ ] SBOM generation for the project itself (recommended for security tools)

Contributions are welcome! Feel free to open issues or submit Pull Requests.

---

## 📝 License

This project is intended for **educational and ethical hacking / penetration testing purposes only**.  
Any unauthorized use against systems without permission is strictly prohibited.

---

## 👨‍💻 Author

**Built by Cybersecurity Researcher — séç gúy**

---

## ⭐ Support

If you find Vulnora useful, please give it a ⭐ on GitHub!

Questions, suggestions, bug reports, or feature requests are welcome via GitHub Issues.

**Stay ethical. Scan responsibly.**

Made with ❤️ for the cybersecurity community.
```
