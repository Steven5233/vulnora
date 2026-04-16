import streamlit as st
import requests
import pandas as pd
import time
import json
import os
from datetime import datetime

API_BASE = os.getenv("API_BASE", "http://localhost:8000")

st.set_page_config(
    page_title="Vulnora",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/Steven5233/vulnora",
        "Report a bug": "https://github.com/Steven5233/vulnora/issues",
        "About": "Vulnora - Vulnerability Management Platform"
    }
)

st.markdown("""
<style>
    .main {background-color: #0a0e17; color: #e2e8f0;}
    .stApp {background-color: #0a0e17;}
    h1 {font-size: 2.8rem; font-weight: 700; color: #67e8f9; margin-bottom: 0.2rem;}
    h2 {font-size: 1.8rem; font-weight: 600; color: #e2e8f0;}
    .card {background: #1e2937; padding: 1.8rem; border-radius: 12px; box-shadow: 0 4px 25px rgba(0,0,0,0.4); margin-bottom: 1.5rem; border: 1px solid #334155;}
    .metric-card {background: linear-gradient(135deg, #1e2937, #334155); border-radius: 12px; padding: 1.6rem; text-align: center; border: 1px solid #334155;}
    .severity-critical {color: #ef4444; font-weight: bold;}
    .severity-high {color: #f97316; font-weight: bold;}
    .severity-medium {color: #eab308; font-weight: bold;}
    .severity-low {color: #22d3ee; font-weight: bold;}
    .severity-info {color: #64748b;}
    .status-running {color: #22c55e; font-weight: 600;}
    .status-completed {color: #3b82f6; font-weight: 600;}
    .nav-link {font-size: 1.05rem;}
    .section-header {border-bottom: 2px solid #334155; padding-bottom: 0.5rem; margin-bottom: 1.2rem;}
    .proxy-history {font-family: monospace; font-size: 0.92rem;}
    .builder-credit {color: #64748b; font-size: 0.85rem; text-align: center; margin-top: 2rem; opacity: 0.8;}
</style>
""", unsafe_allow_html=True)

for key in ["token", "user", "role", "current_scan_id", "polling", "scan_start_time", "zap_history"]:
    if key not in st.session_state:
        st.session_state[key] = None if key not in ["polling", "zap_history"] else False

def get_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}

def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", headers=get_headers(), timeout=15, params=params)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API Connection Error: {str(e)}")
        return None
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return None

def api_post(endpoint, json_data=None):
    try:
        r = requests.post(f"{API_BASE}/{endpoint}", json=json_data, headers=get_headers(), timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API Connection Error: {str(e)}")
        return None
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return None

def api_delete(endpoint):
    try:
        r = requests.delete(f"{API_BASE}/{endpoint}", headers=get_headers(), timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return False

if not st.session_state.token:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align:center;'>Vulnora</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:#94a3b8; font-size:1.15rem;'>Advanced Vulnerability Platform</p>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:#64748b;'>Real-Time Scanning • Logic Flaws • Automated & Manual Testing • Global Compliance</p>", unsafe_allow_html=True)
        tab1, tab2 = st.tabs(["Sign In", "Register"])
        with tab1:
            username = st.text_input("Username", value="admin", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            if st.button("Sign In", type="primary", use_container_width=True):
                try:
                    resp = requests.post(f"{API_BASE}/auth/token", data={"username": username, "password": password}, timeout=10)
                    resp.raise_for_status()
                    st.session_state.token = resp.json()["access_token"]
                    me = requests.get(f"{API_BASE}/users/me", headers=get_headers(), timeout=10)
                    user_data = me.json()
                    st.session_state.user = user_data
                    st.session_state.role = user_data.get("role", "user")
                    st.success(f"Welcome back, {username}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Login failed: {str(e)}")
        with tab2:
            reg_username = st.text_input("Username", key="reg_username")
            reg_email = st.text_input("Email", key="reg_email")
            reg_password = st.text_input("Password", type="password", key="reg_password")
            if st.button("Create Account", type="primary", use_container_width=True):
                if all([reg_username, reg_email, reg_password]):
                    try:
                        payload = {"username": reg_username, "email": reg_email, "password": reg_password}
                        requests.post(f"{API_BASE}/auth/register", json=payload, timeout=10).raise_for_status()
                        st.success("Account created successfully. Please sign in.")
                    except Exception as e:
                        st.error(f"Registration failed: {str(e)}")
    st.stop()

with st.sidebar:
    st.image("https://via.placeholder.com/180x50/0a0e17/67e8f9?text=VULNORA", width=180)
    st.markdown("### Vulnora")
    pages = {
        "Dashboard": "dashboard",
        "Assets": "assets",
        "Launch Scan": "scan",
        "Live Results": "results",
        "Scan History": "history",
        "Reports": "reports",
        "Compliance": "compliance",
        "Proxy Dashboard": "proxy",
        "Repeater": "repeater",
        "IDORForge Pro": "idorforge"
    }
    if st.session_state.role == "admin":
        pages["Administration"] = "admin"
    selection = st.radio("Navigation", list(pages.keys()), label_visibility="collapsed")
    current_page = pages[selection]
    st.divider()
    st.success(f"{st.session_state.user.get('username')} • {st.session_state.role.upper()}")
    if st.button("Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

st.markdown(f"<h1>Vulnora • {st.session_state.user.get('username')}</h1>", unsafe_allow_html=True)
st.caption("Real-Time Scanning • Logic Flaws • Automated & Manual Testing • Global Compliance")

def show_dashboard():
    st.markdown("### Overview")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Assets", "28", "↑4")
    with col2:
        st.metric("Critical Findings", "7", "↓2")
    with col3:
        st.metric("Scans Today", "12")
    with col4:
        st.metric("Risk Score", "42", "↓")
    st.divider()
    st.subheader("Recent Activity")
    recent = api_get("scans/?limit=5")
    if recent:
        df = pd.DataFrame(recent)
        st.dataframe(df, use_container_width=True)

def show_assets():
    st.subheader("Target Assets")
    with st.form("add_asset"):
        target = st.text_input("Target URL / IP")
        if st.form_submit_button("Add Asset"):
            result = api_post("assets/", {"target": target})
            if result:
                st.success("Asset added successfully")
    assets = api_get("assets/")
    if assets:
        df = pd.DataFrame(assets)
        st.dataframe(df, use_container_width=True)

def show_scan():
    st.subheader("Launch New Scan")
    target = st.text_input("Target", placeholder="https://example.com")
    modules = st.multiselect("Scan Modules", ["nuclei", "zap", "logic_flaws", "idorforge"])
    with st.expander("Authentication (Optional)"):
        auth_type = st.radio("Auth Type", ["None", "Cookies (JSON)", "JWT"], horizontal=True)
        auth_info = {}
        if auth_type == "Cookies (JSON)":
            cookies_str = st.text_area("Cookies JSON", '{"session":"abc123"}')
            try:
                auth_info["cookies"] = json.loads(cookies_str)
            except:
                st.warning("Invalid JSON")
        elif auth_type == "JWT":
            auth_info["jwt"] = st.text_input("JWT Token")
    if st.button("Start Scan", type="primary"):
        payload = {"target": target, "modules": modules, "auth_info": auth_info}
        result = api_post("scans/", payload)
        if result and "scan_id" in result:
            st.session_state.current_scan_id = result["scan_id"]
            st.session_state.scan_start_time = time.time()
            st.success("Scan started successfully")
            st.rerun()

def show_live_progress(scan_id):
    placeholder = st.empty()
    start_time = st.session_state.get("scan_start_time") or time.time()
    while True:
        scan = api_get(f"scans/{scan_id}")
        if not scan:
            placeholder.error("Failed to fetch scan status.")
            break
        status = scan.get("status", "unknown")
        risk = scan.get("risk_score", "N/A")
        elapsed = int(time.time() - start_time)
        with placeholder.container():
            st.markdown("### Scan Progress")
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                if status == "running":
                    st.progress(70)
                    st.markdown(f"<span class='status-running'>● RUNNING</span>", unsafe_allow_html=True)
                elif status == "completed":
                    st.progress(100)
                    st.markdown(f"<span class='status-completed'>● COMPLETED</span>", unsafe_allow_html=True)
                else:
                    st.progress(30)
                    st.info(f"Status: {status}")
            with col2:
                st.metric("Risk Score", risk)
            with col3:
                st.metric("Elapsed", f"{elapsed}s")
            if status in ["completed", "failed"]:
                break
        time.sleep(3)

def show_results():
    if st.session_state.get("current_scan_id"):
        scan = api_get(f"scans/{st.session_state.current_scan_id}")
        if scan:
            st.json(scan)
            if scan.get("status") == "running":
                show_live_progress(st.session_state.current_scan_id)
    else:
        st.info("No active scan. Start one from Launch Scan.")

def show_history():
    scans = api_get("scans/")
    if scans:
        df = pd.DataFrame(scans)
        st.dataframe(df, use_container_width=True)

def show_reports():
    st.subheader("Reports")
    scans = api_get("scans/")
    if scans:
        for s in scans:
            if st.button(f"Generate Report for Scan {s.get('id')}"):
                st.info("Report generation started (simulated in frontend)")

def show_compliance():
    st.subheader("Compliance Mapping")
    st.write("NIST • ISO 27001 • GDPR • PCI-DSS")

def show_proxy():
    st.subheader("🕵️ ZAP Proxy Dashboard")
    st.markdown("**Setup Instructions**")
    st.info("""
    1. Configure your browser proxy to **http://localhost:8090**  
    2. Install ZAP Root CA: [Download Root CA](http://localhost:8080/OTHER/core/other/rootcert/)  
    3. Enable HTTPS decryption in ZAP
    """)
    st.divider()
    st.subheader("Intercepted Requests")
    if "zap_history" not in st.session_state or not st.session_state.zap_history:
        st.session_state.zap_history = api_get("zap/history") or []
    if st.session_state.zap_history:
        for req in st.session_state.zap_history[-10:]:
            st.markdown(f"<div class='proxy-history'>**{req.get('method')}** {req.get('url')} → {req.get('status')}</div>", unsafe_allow_html=True)
    else:
        st.info("No intercepted requests yet. Browse through the proxy.")
    if st.button("Refresh Proxy History"):
        st.session_state.zap_history = api_get("zap/history") or []
        st.rerun()

def show_repeater():
    st.subheader("🔁 Repeater")
    col1, col2 = st.columns([1, 1])
    with col1:
        method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE"])
        url = st.text_input("URL", "http://localhost:3000/api/test")
        headers = st.text_area("Headers (JSON)", "{}", height=150)
        body = st.text_area("Body", "", height=200)
    with col2:
        st.markdown("**Response**")
        response_placeholder = st.empty()
    if st.button("Send Request", type="primary"):
        try:
            hdr = json.loads(headers) if headers.strip() else {}
            resp = requests.request(method, url, headers=hdr, json=json.loads(body) if body.strip() else None, timeout=15)
            response_placeholder.json({
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:2000]
            })
        except Exception as e:
            response_placeholder.error(f"Request failed: {str(e)}")

def show_idorforge_pro():
    st.markdown("### 🛡️ IDORForge Pro")
    st.caption("Advanced IDOR + Role-Based Privilege Escalation + Business Logic Flaw Hunter")
    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target (e.g. example.com or full URL)", key="idor_target")
    with col2:
        run_btn = st.button("🚀 Run IDORForge Pro Hunt", type="primary", use_container_width=True)
    with st.expander("Authentication (Cookies / JWT)"):
        auth_type = st.radio("Auth Type", ["None", "Cookies (JSON)", "JWT"], horizontal=True)
        auth_data = {}
        if auth_type == "Cookies (JSON)":
            auth_data["cookies"] = st.text_area("Cookies JSON", '{"session":"abc123"}', height=100)
        elif auth_type == "JWT":
            auth_data["jwt"] = st.text_input("JWT Token")
    if run_btn and target:
        with st.spinner("Running IDORForge Pro..."):
            payload = {
                "target": target,
                "modules": ["idorforge"],
                "auth_info": auth_data
            }
            result = api_post("scans/", json_data=payload)
            if result and "scan_id" in result:
                st.session_state.current_scan_id = result["scan_id"]
                st.session_state.scan_start_time = time.time()
                st.success("IDORForge Pro scan started!")
                show_live_progress(result["scan_id"])
            else:
                st.error("Failed to start IDORForge Pro scan")
    if st.session_state.get("current_scan_id"):
        scan = api_get(f"scans/{st.session_state.current_scan_id}")
        if scan and scan.get("modules") and "idorforge" in scan.get("modules", {}):
            st.subheader("🧪 IDORForge Pro Findings")
            findings = scan["modules"]["idorforge"].get("data", [])
            if findings:
                df = pd.DataFrame(findings)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No findings yet – keep hunting!")
    st.divider()
    st.markdown("**Manual IDOR Tester**")
    st.info("Use the Repeater tab above for manual PoC replay and testing.")

def show_admin():
    st.subheader("Administration")
    st.write("Admin panel controls (users, settings, etc.)")

if current_page == "dashboard":
    show_dashboard()
elif current_page == "assets":
    show_assets()
elif current_page == "scan":
    show_scan()
elif current_page == "results":
    show_results()
elif current_page == "history":
    show_history()
elif current_page == "reports":
    show_reports()
elif current_page == "compliance":
    show_compliance()
elif current_page == "proxy":
    show_proxy()
elif current_page == "repeater":
    show_repeater()
elif current_page == "idorforge":
    show_idorforge_pro()
elif current_page == "admin":
    show_admin()
