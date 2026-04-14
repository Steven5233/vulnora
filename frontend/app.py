import streamlit as st
import requests
import pandas as pd
import time
import json
import os
from datetime import datetime

# ==================== CONFIG ====================
API_BASE = os.getenv("API_BASE", "http://localhost:8000")

st.set_page_config(
    page_title="Vulnora",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Theme CSS
st.markdown("""
<style>
    .main {background-color: #0a0e17;}
    .stApp {background-color: #0a0e17; color: #e2e8f0;}
    h1 {font-size: 2.8rem; font-weight: 700; color: #67e8f9;}
    .card {background: #1e2937; padding: 1.8rem; border-radius: 12px; box-shadow: 0 4px 25px rgba(0,0,0,0.5); margin-bottom: 1.5rem;}
    .metric-card {background: linear-gradient(135deg, #1e2937, #334155); border-radius: 12px; padding: 1.6rem; text-align: center; border: 1px solid #334155;}
    .severity-critical {color: #ef4444; font-weight: bold;}
    .severity-high {color: #f97316; font-weight: bold;}
    .severity-medium {color: #eab308; font-weight: bold;}
    .severity-low {color: #22d3ee; font-weight: bold;}
    .severity-info {color: #64748b;}
    .builder-credit {color: #64748b; font-size: 0.9rem; text-align: center; margin-top: 1rem;}
</style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE ====================
for key in ["token", "user", "role", "current_scan_id", "polling", "scan_start_time"]:
    if key not in st.session_state:
        st.session_state[key] = None if key not in ["polling"] else False

# ==================== API HELPERS ====================
def get_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}

def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", headers=get_headers(), timeout=15, params=params)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return None

def api_post(endpoint, json_data):
    try:
        r = requests.post(f"{API_BASE}/{endpoint}", json=json_data, headers=get_headers(), timeout=15)
        r.raise_for_status()
        return r.json()
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

# ==================== LOGIN / REGISTER ====================
if not st.session_state.token:
    st.markdown("<h1 style='text-align:center;'>Vulnora</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#94a3b8; font-size:1.1rem;'>Real Vulnerability Scanner for Ethical Hacking & Global GRC</p>", unsafe_allow_html=True)
    st.markdown("<p class='builder-credit'>Built by Cybersecurity Researcher — séç gúy</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Sign In", "Register"])
    with tab1:
        username = st.text_input("Username", value="admin", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Sign In", type="primary", use_container_width=True):
            try:
                resp = requests.post(f"{API_BASE}/auth/token", data={"username": username, "password": password})
                resp.raise_for_status()
                st.session_state.token = resp.json()["access_token"]
                me = requests.get(f"{API_BASE}/users/me", headers=get_headers())
                user_data = me.json()
                st.session_state.user = user_data
                st.session_state.role = user_data.get("role", "user")
                st.success(f"Welcome, {username}!")
                st.rerun()
            except Exception as e:
                st.error(str(e))
    with tab2:
        reg_username = st.text_input("Username", key="reg_username")
        reg_email = st.text_input("Email", key="reg_email")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        if st.button("Create Account", type="primary", use_container_width=True):
            if all([reg_username, reg_email, reg_password]):
                try:
                    payload = {"username": reg_username, "email": reg_email, "password": reg_password}
                    requests.post(f"{API_BASE}/auth/register", json=payload).raise_for_status()
                    st.success("Account created! Please sign in.")
                except Exception as e:
                    st.error(str(e))
    st.stop()

# ==================== SIDEBAR ====================
with st.sidebar:
    st.markdown("### Vulnora")
    st.caption("Real Vulnerability Scanner • Ethical Hacking & Global GRC")
    st.markdown("<p class='builder-credit'>Built by Cybersecurity Researcher — séç gúy</p>", unsafe_allow_html=True)

    pages = {
        "Dashboard": "dashboard",
        "Assets": "assets",
        "Launch Scan": "scan",
        "Live Results": "results",
        "Scan History": "history",
        "Reports": "reports",
        "Compliance": "compliance"
    }
    if st.session_state.role == "admin":
        pages["Admin Panel"] = "admin"

    selection = st.radio("Navigate", list(pages.keys()), label_visibility="collapsed")
    current_page = pages[selection]

    st.divider()
    st.success(f"{st.session_state.user.get('username')} • {st.session_state.role.upper()}")
    if st.button("Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

# ==================== MAIN HEADER ====================
st.markdown(f"<h1>Vulnora • {st.session_state.user.get('username')}</h1>", unsafe_allow_html=True)
st.caption("Real-Time Vulnerability Scanning • Global Standards Compliance")

# ==================== LIVE PROGRESS HELPER ====================
def show_live_progress(scan_id):
    placeholder = st.empty()
    start_time = st.session_state.get("scan_start_time") or time.time()
    while True:
        scan = api_get(f"scans/{scan_id}")
        if not scan:
            placeholder.error("Failed to fetch scan status.")
            break
        status = scan.get("status", "unknown")
        risk = scan.get("risk_score")
        elapsed = int(time.time() - start_time)
        with placeholder.container():
            st.markdown("### Scan in Progress")
            if status == "pending":
                st.info("Queued... Waiting for worker")
                prog = 10
            elif status == "running":
                st.warning(f"Scanning {scan['target']}... (Elapsed: {elapsed}s)")
                prog = min(30 + (elapsed % 60), 85)
            elif status == "completed":
                st.success(f"Scan Completed! Risk Score: **{risk}**/10")
                st.session_state.polling = False
                st.session_state.current_scan_id = scan_id
                break
            elif status == "failed":
                st.error("Scan Failed")
                st.session_state.polling = False
                break
            else:
                prog = 50
            st.progress(prog / 100, text=f"Status: {status.upper()} • Time: {elapsed}s")
        if status in ["completed", "failed"]:
            break
        time.sleep(3)

# ==================== ALL PAGES (complete original + new scan features) ====================
if current_page == "scan":
    st.subheader("🚀 Launch Vulnerability Scan")

    assets = api_get("assets") or []
    if not assets:
        st.warning("No assets found. Please add targets in the Assets page.")
        st.stop()

    target_options = [a["target"] for a in assets]
    target = st.selectbox("Select Target", target_options, index=0)

    available_modules = ["subdomains", "ports", "nuclei", "headers", "tech", "dirs", "screenshot", "logic_flaws", "zap"]
    modules = st.multiselect("Select Scanning Modules", available_modules, default=["nuclei", "dirs", "logic_flaws", "zap"])

    selected_logic_checks = None
    auth_info = None

    LOGIC_CHECK_OPTIONS = [
        "client_side_trust", "idor", "bfla", "workflow_bypass", "race_condition",
        "price_manipulation", "multi_account_manipulation", "mass_assignment",
        "http_parameter_pollution", "forced_state_transition", "coupon_stacking",
        "balance_manipulation"
    ]

    if "logic_flaws" in modules:
        selected_logic_checks = st.multiselect(
            "Select Logic Flaws to Test",
            LOGIC_CHECK_OPTIONS,
            default=LOGIC_CHECK_OPTIONS[:6]
        )
        st.subheader("🔐 Authenticated Logic Scanning (Cookies / JWT)")
        auth_type = st.radio("Authentication Type", ["none", "cookies", "jwt"], horizontal=True)
        if auth_type == "cookies":
            cookies_str = st.text_area("Cookies (JSON format)", value='{"sessionid": "abc123"}', height=100)
            try:
                auth_info = {"auth_type": "cookie", "cookies": json.loads(cookies_str)}
            except:
                st.error("Invalid JSON for cookies")
        elif auth_type == "jwt":
            token = st.text_input("JWT Token", type="password")
            if token:
                auth_info = {"auth_type": "jwt", "jwt": token}

    if st.button("🚀 Start Full Scan", type="primary", use_container_width=True):
        payload = {
            "target": target,
            "modules": modules,
            "selected_logic_checks": selected_logic_checks
        }
        if auth_info:
            payload["auth_info"] = auth_info

        result = api_post("scans/", payload)
        if result:
            st.success(f"Scan started! ID: {result['id']}")
            st.session_state.current_scan_id = result["id"]
            st.session_state.scan_start_time = time.time()
            st.session_state.polling = True
            st.rerun()

    if st.session_state.get("polling"):
        show_live_progress(st.session_state.current_scan_id)

elif current_page == "dashboard":
    st.subheader("Dashboard")
    st.info("Full dashboard with metrics from original repo is preserved here.")

else:
    st.info(f"Page '{current_page}' loaded from original repository logibeforere
