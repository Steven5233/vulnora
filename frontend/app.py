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
        "About": "Vulnora - Vulnerability Management Platform • Built by séç gúy"
    }
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    * {font-family: 'Inter', sans-serif;}
    .main {background-color: #060b14; color: #e2e8f0;}
    .stApp {background-color: #060b14;}
    .stSidebar {background-color: #0a0e1a; border-right: 1px solid #1e2d45;}
    .stSidebar .stRadio label {font-size: 0.95rem; padding: 0.3rem 0;}

    h1 {font-size: 2.6rem; font-weight: 700; color: #67e8f9; margin-bottom: 0.1rem; letter-spacing: -0.5px;}
    h2 {font-size: 1.7rem; font-weight: 600; color: #e2e8f0;}
    h3 {color: #cbd5e1;}

    .stButton > button {
        background: linear-gradient(135deg, #0ea5e9, #6366f1);
        color: white; border: none; border-radius: 8px;
        font-weight: 600; transition: all 0.2s ease;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(99,102,241,0.4);
    }

    .card {
        background: #0f1829;
        padding: 1.8rem; border-radius: 14px;
        box-shadow: 0 4px 30px rgba(0,0,0,0.5);
        margin-bottom: 1.5rem;
        border: 1px solid #1e2d45;
    }
    .metric-card {
        background: linear-gradient(135deg, #0f1829, #1a2540);
        border-radius: 14px; padding: 1.6rem;
        text-align: center; border: 1px solid #1e2d45;
        transition: transform 0.2s;
    }
    .metric-card:hover {transform: translateY(-2px);}

    .severity-critical {color: #ef4444; font-weight: 700; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px;}
    .severity-high     {color: #f97316; font-weight: 700; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px;}
    .severity-medium   {color: #eab308; font-weight: 700; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px;}
    .severity-low      {color: #22d3ee; font-weight: 700; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px;}
    .severity-info     {color: #64748b;}

    .status-running   {color: #22c55e; font-weight: 600;}
    .status-completed {color: #3b82f6; font-weight: 600;}
    .status-failed    {color: #ef4444; font-weight: 600;}

    .proxy-history {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.88rem; padding: 0.4rem 0;
        border-bottom: 1px solid #1e2d45;
    }
    .finding-row {
        background: #0f1829; border-radius: 10px;
        padding: 1rem 1.2rem; margin-bottom: 0.7rem;
        border-left: 4px solid #334155;
        transition: border-color 0.2s;
    }
    .finding-row.critical {border-left-color: #ef4444;}
    .finding-row.high     {border-left-color: #f97316;}
    .finding-row.medium   {border-left-color: #eab308;}
    .finding-row.low      {border-left-color: #22d3ee;}

    .brand-tag {
        color: #475569; font-size: 0.78rem;
        text-align: center; margin-top: 1.5rem;
        font-style: italic; letter-spacing: 0.3px;
    }
    .brand-tag span {color: #67e8f9; font-weight: 600; font-style: normal;}

    .login-box {
        background: #0f1829; border-radius: 16px;
        padding: 2.5rem; border: 1px solid #1e2d45;
        box-shadow: 0 8px 40px rgba(0,0,0,0.6);
    }
    .section-header {
        border-bottom: 2px solid #1e2d45;
        padding-bottom: 0.5rem; margin-bottom: 1.2rem;
    }
    .tag-pill {
        display: inline-block; padding: 0.2rem 0.7rem;
        border-radius: 20px; font-size: 0.75rem; font-weight: 600;
        margin-right: 0.4rem;
    }
    .tag-critical {background: rgba(239,68,68,0.15); color: #ef4444;}
    .tag-high     {background: rgba(249,115,22,0.15); color: #f97316;}
    .tag-medium   {background: rgba(234,179,8,0.15);  color: #eab308;}
    .tag-low      {background: rgba(34,211,238,0.15); color: #22d3ee;}
</style>
""", unsafe_allow_html=True)

for key, default in {
    "token": None, "user": None, "role": None,
    "current_scan_id": None, "polling": False,
    "scan_start_time": None, "zap_history": None
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

def get_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}

def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", headers=get_headers(), timeout=15, params=params)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to Vulnora API. Is the backend running?")
        return None
    except requests.exceptions.RequestException as e:
        st.error(f"API Error: {str(e)}")
        return None

def api_post(endpoint, json_data=None):
    try:
        r = requests.post(f"{API_BASE}/{endpoint}", json=json_data, headers=get_headers(), timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to Vulnora API. Is the backend running?")
        return None
    except requests.exceptions.RequestException as e:
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

def severity_pill(severity: str) -> str:
    s = severity.lower()
    return f"<span class='tag-pill tag-{s}'>{s.upper()}</span>"

if not st.session_state.token:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
            <div style='text-align:center; padding: 2rem 0 1rem;'>
                <div style='font-size:3rem;'>🛡️</div>
                <h1 style='text-align:center; font-size:2.8rem;'>Vulnora</h1>
                <p style='color:#94a3b8; font-size:1.1rem; margin-top:0.3rem;'>Advanced Vulnerability Management Platform</p>
                <p style='color:#475569; font-size:0.88rem;'>Real-Time Scanning • Logic Flaws • Automated & Manual Testing • Global Compliance</p>
            </div>
        """, unsafe_allow_html=True)
        st.markdown("<div class='login-box'>", unsafe_allow_html=True)
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
                    st.success(f"Welcome back, {username} 👋")
                    st.rerun()
                except Exception as e:
                    st.error(f"Login failed: {str(e)}")
        with tab2:
            reg_username = st.text_input("Username", key="reg_username")
            reg_email    = st.text_input("Email",    key="reg_email")
            reg_password = st.text_input("Password", type="password", key="reg_password")
            if st.button("Create Account", type="primary", use_container_width=True):
                if all([reg_username, reg_email, reg_password]):
                    try:
                        requests.post(f"{API_BASE}/auth/register", json={"username": reg_username, "email": reg_email, "password": reg_password}, timeout=10).raise_for_status()
                        st.success("Account created. Please sign in.")
                    except Exception as e:
                        st.error(f"Registration failed: {str(e)}")
                else:
                    st.warning("Please fill all fields.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='brand-tag'>Built by <span>séç gúy</span> — Cybersecurity Researcher</div>", unsafe_allow_html=True)
    st.stop()

with st.sidebar:
    st.markdown("""
        <div style='text-align:center; padding: 1rem 0 0.5rem;'>
            <div style='font-size:1.8rem;'>🛡️</div>
            <div style='color:#67e8f9; font-size:1.2rem; font-weight:700; letter-spacing:1px;'>VULNORA</div>
            <div style='color:#475569; font-size:0.72rem; margin-top:2px;'>by séç gúy</div>
        </div>
    """, unsafe_allow_html=True)
    st.divider()

    pages = {
        "📊 Dashboard":      "dashboard",
        "🎯 Assets":         "assets",
        "🚀 Launch Scan":    "scan",
        "📡 Live Results":   "results",
        "🕘 Scan History":   "history",
        "📄 Reports":        "reports",
        "✅ Compliance":     "compliance",
        "🕵️ Proxy Dashboard": "proxy",
        "🔁 Repeater":       "repeater",
        "🛡️ IDORForge Pro":  "idorforge",
    }
    if st.session_state.role == "admin":
        pages["⚙️ Administration"] = "admin"

    selection    = st.radio("Navigation", list(pages.keys()), label_visibility="collapsed")
    current_page = pages[selection]

    st.divider()
    st.markdown(f"""
        <div style='background:#0f1829; border-radius:10px; padding:0.8rem 1rem; border:1px solid #1e2d45;'>
            <div style='color:#67e8f9; font-weight:600; font-size:0.9rem;'>👤 {st.session_state.user.get('username')}</div>
            <div style='color:#475569; font-size:0.75rem; margin-top:2px;'>{st.session_state.role.upper()}</div>
        </div>
    """, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()
    st.markdown("<div class='brand-tag' style='margin-top:1rem;'>Built by <span>séç gúy</span><br>Cybersecurity Researcher</div>", unsafe_allow_html=True)

st.markdown(f"<h1>🛡️ Vulnora</h1>", unsafe_allow_html=True)
st.caption(f"Logged in as **{st.session_state.user.get('username')}** • Real-Time Scanning • Logic Flaws • Automated & Manual Testing • Global Compliance")
st.divider()

def show_dashboard():
    st.markdown("### 📊 Overview")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Assets",      "28", "↑4",  delta_color="normal")
    with col2:
        st.metric("Critical Findings", "7",  "↓2",  delta_color="inverse")
    with col3:
        st.metric("Scans Today",       "12")
    with col4:
        st.metric("Risk Score",        "42", "↓8",  delta_color="inverse")
    st.divider()

    col_a, col_b = st.columns([2, 1])
    with col_a:
        st.subheader("Recent Scans")
        recent = api_get("scans/?limit=5")
        if recent:
            df = pd.DataFrame(recent)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No recent scans found.")
    with col_b:
        st.subheader("Severity Breakdown")
        st.markdown("""
            <div style='display:flex; flex-direction:column; gap:0.5rem; margin-top:0.5rem;'>
                <div style='display:flex; justify-content:space-between; padding:0.5rem 0.8rem; background:#1a0a0a; border-radius:8px;'>
                    <span class='severity-critical'>● Critical</span><span style='color:#ef4444; font-weight:700;'>7</span>
                </div>
                <div style='display:flex; justify-content:space-between; padding:0.5rem 0.8rem; background:#1a1000; border-radius:8px;'>
                    <span class='severity-high'>● High</span><span style='color:#f97316; font-weight:700;'>14</span>
                </div>
                <div style='display:flex; justify-content:space-between; padding:0.5rem 0.8rem; background:#1a1500; border-radius:8px;'>
                    <span class='severity-medium'>● Medium</span><span style='color:#eab308; font-weight:700;'>23</span>
                </div>
                <div style='display:flex; justify-content:space-between; padding:0.5rem 0.8rem; background:#001a1a; border-radius:8px;'>
                    <span class='severity-low'>● Low</span><span style='color:#22d3ee; font-weight:700;'>41</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

def show_assets():
    st.subheader("🎯 Target Assets")
    with st.form("add_asset", clear_on_submit=True):
        col1, col2 = st.columns([4, 1])
        with col1:
            target = st.text_input("Target URL / IP", placeholder="https://example.com or 192.168.1.1")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            submitted = st.form_submit_button("➕ Add Asset", use_container_width=True)
        if submitted:
            if target:
                result = api_post("assets/", {"target": target})
                if result:
                    st.success(f"Asset **{target}** added successfully.")
            else:
                st.warning("Please enter a target.")
    st.divider()
    assets = api_get("assets/")
    if assets:
        df = pd.DataFrame(assets)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No assets added yet.")

def show_scan():
    st.subheader("🚀 Launch New Scan")
    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target", placeholder="https://example.com")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)

    modules = st.multiselect(
        "Scan Modules",
        ["nuclei", "zap", "logic_flaws", "idorforge"],
        default=["logic_flaws"],
        help="Select one or more modules to run against the target."
    )

    with st.expander("🔐 Authentication (Optional)"):
        auth_type = st.radio("Auth Type", ["None", "Cookies (JSON)", "JWT"], horizontal=True)
        auth_info = {}
        if auth_type == "Cookies (JSON)":
            cookies_str = st.text_area("Cookies JSON", '{"session":"abc123"}', height=80)
            try:
                auth_info["cookies"] = json.loads(cookies_str)
            except Exception:
                st.warning("Invalid JSON for cookies.")
        elif auth_type == "JWT":
            auth_info["jwt"] = st.text_input("JWT Token")

    with st.expander("⚙️ Advanced Options"):
        aggression = st.select_slider("Aggression Level", options=["low", "medium", "high"], value="medium")
        auth_info["aggression"] = aggression

    if st.button("🚀 Start Scan", type="primary", use_container_width=False):
        if not target:
            st.warning("Please enter a target URL.")
        elif not modules:
            st.warning("Please select at least one scan module.")
        else:
            payload = {"target": target, "modules": modules, "auth_info": auth_info}
            result  = api_post("scans/", payload)
            if result and "scan_id" in result:
                st.session_state.current_scan_id = result["scan_id"]
                st.session_state.scan_start_time = time.time()
                st.success(f"✅ Scan `{result['scan_id']}` started successfully.")
                st.rerun()

def show_live_progress(scan_id):
    placeholder  = st.empty()
    start_time   = st.session_state.get("scan_start_time") or time.time()
    while True:
        scan = api_get(f"scans/{scan_id}")
        if not scan:
            placeholder.error("Failed to fetch scan status.")
            break
        status  = scan.get("status", "unknown")
        risk    = scan.get("risk_score", "N/A")
        elapsed = int(time.time() - start_time)
        with placeholder.container():
            st.markdown("### 📡 Scan Progress")
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                if status == "running":
                    st.progress(70)
                    st.markdown("<span class='status-running'>● RUNNING</span>", unsafe_allow_html=True)
                elif status == "completed":
                    st.progress(100)
                    st.markdown("<span class='status-completed'>● COMPLETED</span>", unsafe_allow_html=True)
                elif status == "failed":
                    st.progress(0)
                    st.markdown("<span class='status-failed'>● FAILED</span>", unsafe_allow_html=True)
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
    st.subheader("📡 Live Results")
    if st.session_state.get("current_scan_id"):
        scan = api_get(f"scans/{st.session_state.current_scan_id}")
        if scan:
            col1, col2, col3 = st.columns(3)
            col1.metric("Scan ID",    str(scan.get("id", "—")))
            col2.metric("Status",     scan.get("status", "—").upper())
            col3.metric("Risk Score", scan.get("risk_score", "—"))
            st.divider()
            if scan.get("status") == "running":
                show_live_progress(st.session_state.current_scan_id)
            with st.expander("📋 Full Scan JSON"):
                st.json(scan)
    else:
        st.info("No active scan. Launch one from **🚀 Launch Scan**.")

def show_history():
    st.subheader("🕘 Scan History")
    scans = api_get("scans/")
    if scans:
        df = pd.DataFrame(scans)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption(f"{len(scans)} total scans recorded.")
    else:
        st.info("No scan history available.")

def show_reports():
    st.subheader("📄 Reports")
    scans = api_get("scans/")
    if scans:
        for s in scans:
            col1, col2 = st.columns([4, 1])
            with col1:
                st.markdown(f"**Scan** `{s.get('id')}` — {s.get('target', 'Unknown')} — {s.get('status', '').upper()}")
            with col2:
                if st.button("Generate", key=f"report_{s.get('id')}"):
                    st.info(f"Report generation queued for scan `{s.get('id')}`")
    else:
        st.info("No scans available to report on.")

def show_compliance():
    st.subheader("✅ Compliance Mapping")
    st.markdown("""
        <div style='display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-top:1rem;'>
            <div class='card'>
                <div style='font-size:1.1rem; font-weight:700; color:#67e8f9;'>NIST CSF</div>
                <div style='color:#94a3b8; font-size:0.88rem; margin-top:0.4rem;'>Identify • Protect • Detect • Respond • Recover</div>
            </div>
            <div class='card'>
                <div style='font-size:1.1rem; font-weight:700; color:#67e8f9;'>ISO 27001</div>
                <div style='color:#94a3b8; font-size:0.88rem; margin-top:0.4rem;'>Information Security Management System</div>
            </div>
            <div class='card'>
                <div style='font-size:1.1rem; font-weight:700; color:#67e8f9;'>GDPR</div>
                <div style='color:#94a3b8; font-size:0.88rem; margin-top:0.4rem;'>Data Protection & Privacy Compliance</div>
            </div>
            <div class='card'>
                <div style='font-size:1.1rem; font-weight:700; color:#67e8f9;'>PCI-DSS</div>
                <div style='color:#94a3b8; font-size:0.88rem; margin-top:0.4rem;'>Payment Card Industry Data Security Standard</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def show_proxy():
    st.subheader("🕵️ ZAP Proxy Dashboard")
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("**Setup Instructions**")
        st.info("""
1. Configure your browser proxy to **http://localhost:8090**
2. Install ZAP Root CA: [Download Root CA](http://localhost:8080/OTHER/core/other/rootcert/)
3. Enable HTTPS decryption in ZAP
        """)
    with col2:
        st.markdown("**Quick Stats**")
        if st.session_state.zap_history:
            st.metric("Intercepted Requests", len(st.session_state.zap_history))
        else:
            st.metric("Intercepted Requests", 0)

    st.divider()
    st.subheader("Intercepted Requests")

    if not st.session_state.zap_history:
        st.session_state.zap_history = api_get("zap/history") or []

    if st.session_state.zap_history:
        for req in st.session_state.zap_history[-10:]:
            method = req.get("method", "GET")
            url    = req.get("url", "")
            status = req.get("status", "")
            color  = "#22c55e" if str(status).startswith("2") else "#f97316" if str(status).startswith("3") else "#ef4444"
            st.markdown(
                f"<div class='proxy-history'>"
                f"<span style='color:#6366f1; font-weight:600;'>{method}</span> "
                f"<span style='color:#94a3b8;'>{url}</span> "
                f"<span style='color:{color}; font-weight:600;'>→ {status}</span>"
                f"</div>",
                unsafe_allow_html=True
            )
    else:
        st.info("No intercepted requests yet. Browse through the proxy.")

    if st.button("🔄 Refresh Proxy History"):
        st.session_state.zap_history = api_get("zap/history") or []
        st.rerun()

def show_repeater():
    st.subheader("🔁 Repeater")
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("**Request**")
        method  = st.selectbox("Method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
        url     = st.text_input("URL", "http://localhost:3000/api/test")
        headers = st.text_area("Headers (JSON)", "{}", height=120)
        body    = st.text_area("Body (JSON)", "", height=180)
    with col2:
        st.markdown("**Response**")
        response_placeholder = st.empty()

    if st.button("▶ Send Request", type="primary"):
        try:
            hdr      = json.loads(headers) if headers.strip() else {}
            body_obj = json.loads(body) if body.strip() else None
            resp     = requests.request(method, url, headers=hdr, json=body_obj, timeout=15)
            response_placeholder.json({
                "status":  resp.status_code,
                "headers": dict(resp.headers),
                "body":    resp.text[:3000]
            })
        except json.JSONDecodeError:
            response_placeholder.error("Invalid JSON in headers or body.")
        except Exception as e:
            response_placeholder.error(f"Request failed: {str(e)}")

def show_idorforge_pro():
    st.markdown("### 🛡️ IDORForge Pro")
    st.caption("Advanced IDOR • Role-Based Privilege Escalation • Business Logic Flaw Hunter")
    st.divider()

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target URL", placeholder="https://example.com", key="idor_target")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        run_btn = st.button("🚀 Run IDORForge Pro", type="primary", use_container_width=True)

    with st.expander("🔐 Authentication"):
        auth_type = st.radio("Auth Type", ["None", "Cookies (JSON)", "JWT"], horizontal=True, key="idor_auth_type")
        auth_data = {}
        if auth_type == "Cookies (JSON)":
            raw = st.text_area("Cookies JSON", '{"session":"abc123"}', height=80)
            try:
                auth_data["cookies"] = json.loads(raw)
            except Exception:
                st.warning("Invalid JSON for cookies.")
        elif auth_type == "JWT":
            auth_data["jwt"] = st.text_input("JWT Token", key="idor_jwt")

    with st.expander("⚙️ Scan Options"):
        checks = st.multiselect(
            "Logic Checks",
            ["idor", "bfla", "client_side_trust", "race_condition", "mass_assignment",
             "http_parameter_pollution", "workflow_bypass", "price_manipulation",
             "forced_state_transition", "coupon_stacking", "balance_manipulation",
             "multi_account_manipulation"],
            default=["idor", "bfla", "mass_assignment"],
        )
        aggression = st.select_slider("Aggression", options=["low", "medium", "high"], value="medium", key="idor_aggression")
        auth_data["aggression"] = aggression
        if checks:
            auth_data["checks"] = checks

    if run_btn:
        if not target:
            st.warning("Please enter a target URL.")
        else:
            with st.spinner("🔍 Running IDORForge Pro hunt..."):
                payload = {"target": target, "modules": ["idorforge"], "auth_info": auth_data}
                result  = api_post("scans/", json_data=payload)
                if result and "scan_id" in result:
                    st.session_state.current_scan_id = result["scan_id"]
                    st.session_state.scan_start_time = time.time()
                    st.success(f"✅ IDORForge Pro scan started — ID: `{result['scan_id']}`")
                    show_live_progress(result["scan_id"])
                else:
                    st.error("Failed to start IDORForge Pro scan. Check backend connectivity.")

    if st.session_state.get("current_scan_id"):
        scan = api_get(f"scans/{st.session_state.current_scan_id}")
        if scan and "idorforge" in scan.get("modules", {}):
            st.divider()
            st.subheader("🧪 IDORForge Pro Findings")
            findings = scan["modules"]["idorforge"].get("data", [])
            if findings:
                for f in findings:
                    sev = f.get("severity", "info").lower()
                    st.markdown(
                        f"<div class='finding-row {sev}'>"
                        f"{severity_pill(sev)} "
                        f"<strong>{f.get('name', 'Finding')}</strong><br>"
                        f"<span style='color:#64748b; font-size:0.85rem;'>{f.get('poc', {}).get('url', '')}</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                st.divider()
                st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
            else:
                st.info("No findings yet — scan may still be running.")

    st.divider()
    st.markdown("**💡 Manual PoC Testing**")
    st.info("Use the **🔁 Repeater** tab to manually replay and modify captured requests for PoC verification.")

def show_admin():
    st.subheader("⚙️ Administration")
    tab1, tab2 = st.tabs(["Users", "Settings"])
    with tab1:
        st.write("User management panel — connect to `/admin/users` endpoint.")
    with tab2:
        st.write("Platform configuration and API settings.")

page_map = {
    "dashboard": show_dashboard,
    "assets":    show_assets,
    "scan":      show_scan,
    "results":   show_results,
    "history":   show_history,
    "reports":   show_reports,
    "compliance":show_compliance,
    "proxy":     show_proxy,
    "repeater":  show_repeater,
    "idorforge": show_idorforge_pro,
    "admin":     show_admin,
}

if current_page in page_map:
    page_map[current_page]()
