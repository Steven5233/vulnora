# backend/app/constants.py
from datetime import datetime

# Global Compliance Mapping (updated 2026 standards)
COMPLIANCE_MAP = {
    "critical": "ISO 27001: A.12.6.1 + NIST CSF ID.RA-5 + PCI DSS 6.2 + SOC 2 CC7.1 – Immediate remediation required (high risk of material weakness)",
    "high": "ISO 27001: A.12.6 + NIST CSF PR.IP-12 + GDPR Art. 32 + SOC 2 CC6.1 – High priority; document in risk register",
    "medium": "ISO 27001: A.12.6.1 + NIST CSF ID.RA + PCI DSS 11.2 + SOC 2 CC7.2 – Schedule remediation within 90 days",
    "low": "ISO 27001: A.12.6 + CIS Controls v8 + NIST CSF PR.PT-3 – Best practice; monitor in next cycle",
    "info": "ISO 27001: A.18.2.1 + NIST CSF ID.SC – Logging / awareness improvement",
}

ALLOWED_MODULES = {
    "subdomains", "ports", "nuclei", "headers", "tech", "dirs", "screenshot", "logic_flaws", "zap"   # ← NEW ZAP
}

# Tool configuration for easy extension
TOOL_CONFIG = {
    "subdomains": {"timeout": 90, "cmd_base": ["subfinder", "-d", "{target}", "-silent", "-json"]},
    "ports": {"timeout": 180, "cmd_base": ["nmap", "-F", "-T4", "-oX", "-", "{target}"]},
    "nuclei": {
        "timeout": 480,
        "cmd_base": [
            "nuclei", "-u", "{target}",
            "-t", "http/", "cves/", "vulnerabilities/", "misconfiguration/", "exposures/", "tech/",
            "-severity", "critical,high,medium,low,info",
            "-json", "-silent", "-timeout", "12", "-retries", "2"
        ]
    },
    "httpx": {"timeout": 40, "cmd_base": ["httpx", "-u", "{target}", "-json", "-tech-detect", "-silent"]},

    "headers": {"timeout": 40, "cmd_base": ["httpx", "-u", "{target}", "-json", "-headers", "-silent"]},
    "tech": {"timeout": 40, "cmd_base": ["httpx", "-u", "{target}", "-json", "-tech-detect", "-silent"]},

    "dirs": {
        "timeout": 180,
        "cmd_base": [
            "feroxbuster", "-u", "http://{target}", "--silent",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-t", "50", "--no-state", "--timeout", "8000"
        ]
    },

    "logic_flaws": {"timeout": 300, "custom": True},
    "zap": {"timeout": 600, "custom": True}   # ← NEW OWASP ZAP
}
