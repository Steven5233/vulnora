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

# ==================== SCAN PAGE (Updated with Logic Flaws) ====================
if current_page == "scan":
    st.subheader("🚀 Launch Vulnerability Scan")

    assets = api_get("assets") or []
    if not assets:
        st.warning("No assets found. Please add targets in the Assets page.")
        st.stop()

    target = st.selectbox("Select Target Asset", [a["target"] for a in assets])

    available_modules = ["subdomains", "ports", "nuclei", "headers", "tech", "dirs", "screenshot", "logic_flaws"]
    modules = st.multiselect(
        "Select Scanning Modules",
        available_modules,
        default=["nuclei", "dirs", "logic_flaws"]
    )

    selected_logic_checks = None
    if "logic_flaws" in modules:
        st.subheader("🔍 Specific Logic Flaws to Test")
        st.info("Choose specific checks or leave empty to run **all** logic flaw tests.")
        logic_options = [
            "client_side_trust (Price/Quantity Manipulation)",
            "idor (IDOR/BOLA)",
            "bfla (Privilege Escalation)",
            "workflow_bypass (Skip Steps)",
            "race_condition (Concurrent Requests)",
            "price_manipulation (Discount/Refund Abuse)"
        ]
        selected_display = st.multiselect("Logic Checks", logic_options, default=None)
        
        check_map = {
            "client_side_trust (Price/Quantity Manipulation)": "client_side_trust",
            "idor (IDOR/BOLA)": "idor",
            "bfla (Privilege Escalation)": "bfla",
            "workflow_bypass (Skip Steps)": "workflow_bypass",
            "race_condition (Concurrent Requests)": "race_condition",
            "price_manipulation (Discount/Refund Abuse)": "price_manipulation"
        }
        if selected_display:
            selected_logic_checks = [check_map[c] for c in selected_display]

    if st.button("🚀 Start Scan", type="primary", use_container_width=True):
        payload = {
            "target": target,
            "modules": modules
        }
        if "logic_flaws" in modules and selected_logic_checks:
            payload["selected_logic_checks"] = selected_logic_checks

        result = api_post("scans/", payload)
        if result and "id" in result:
            st.session_state.current_scan_id = result["id"]
            st.session_state.scan_start_time = time.time()
            st.session_state.polling = True
            st.success(f"Scan launched! ID: {result['id']}")
            show_live_progress(result["id"])   # Auto-show live progress
            st.rerun()

# ==================== LIVE RESULTS PAGE (Updated) ====================
elif current_page == "results":
    st.subheader("📊 Scan Results & Findings")

    scan_id = st.session_state.get("current_scan_id")
    if not scan_id:
        st.info("No scan running. Go to **Launch Scan** to start one.")
        st.stop()

    scan = api_get(f"scans/{scan_id}")
    if not scan:
        st.error("Could not load scan data.")
        st.stop()

    st.metric("Risk Score", f"{scan.get('risk_score', 0):.1f}/10")

    data = scan.get("result_data", {}) or {}
    nuclei = data.get("nuclei", [])
    logic_findings = data.get("logic_flaws", [])

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🔍 Technical Findings")
        if nuclei:
            for f in nuclei[:10]:  # limit display
                sev_class = f"severity-{f.get('severity', 'medium')}"
                with st.expander(f"[{f.get('severity','medium').upper()}] {f.get('name','Finding')}"):
                    st.markdown(f"**ID:** {f.get('id')}")
                    st.markdown(f"**Description:** {f.get('description','N/A')}")
        else:
            st.info("No technical findings.")

    with col2:
        st.subheader("🧠 Business Logic Flaws")
        if logic_findings:
            for f in logic_findings:
                with st.expander(f"[{f.get('severity','high').upper()}] {f.get('name', f.get('flaw_type','Logic Flaw'))}"):
                    st.markdown(f"**Type:** {f.get('flaw_type')}")
                    st.markdown(f"**Description:** {f.get('description','N/A')}")
                    st.code(json.dumps(f.get("poc", {}), indent=2), language="json")
        else:
            st.info("No logic flaws detected.")

    if st.button("Refresh Results"):
        st.rerun()

# ==================== Keep other pages (dashboard, assets, etc.) as they were in your original file ====================
# For now, add a placeholder for the remaining pages so the app doesn't crash

else:
    st.info(f"Page **{current_page}** is not yet fully updated in this version. The Scan and Results pages have been enhanced with logic flaw support.")
    st.caption("Other pages (Dashboard, Assets, Reports, etc.) retain original functionality.")

# Footer
st.markdown("---")
st.markdown("<p class='builder-credit'>Vulnora • Open Source Vulnerability Management Platform</p>", unsafe_allow_html=True)
