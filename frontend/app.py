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

for key in ["token", "user", "role", "current_scan_id", "polling", "scan_start_time"]:
    if key not in st.session_state:
        st.session_state[key] = None if key not in ["polling"] else False

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

def api_post(endpoint, json_data=None):
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

if not st.session_state.token:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align:center;'>Vulnora</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:#94a3b8; font-size:1.15rem;'>Vulnora</p>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:#64748b;'>Real-Time Scanning • Logic Flaws • Automated & Manual Testing • Global Compliance</p>", unsafe_allow_html=True)
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
                    st.success(f"Welcome back, {username}")
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
                        st.success("Account created successfully. Please sign in.")
                    except Exception as e:
                        st.error(str(e))
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
        "Repeater": "repeater"
    }
    if st.session_state.role == "admin":
        pages["Administration"] = "admin"
    selection = st.radio("Navigation", list(pages.keys()), label_visibility="collapsed")
    current_page = pages[selection]
    st.divider()
    st.success(f"👤 {st.session_state.user.get('username')} • {st.session_state.role.upper()}")
    if st.button("Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

st.markdown(f"<h1>Vulnora • {st.session_state.user.get('username')}</h1>", unsafe_allow_html=True)
st.caption("Vulnora • Real-Time Vulnerability Scanning • Automated & Manual Testing • Global Compliance")

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
            st.markdown("### Scan Progress")
            col1, col2 = st.columns([3,1])
            with col1:
                if status == "pending":
                    st.info("Queued – Waiting for worker")
                    prog = 10
                elif status == "running":
                    st.warning(f"Scanning **{scan.get('target')}** • Elapsed: {elapsed}s")
                    prog = min(30 + (elapsed % 60), 85)
                elif status == "completed":
                    st.success(f"✅ Scan Completed • Risk Score: **{risk}/10**")
                    st.session_state.polling = False
                    st.session_state.current_scan_id = scan_id
                    break
                elif status == "failed":
                    st.error("❌ Scan Failed")
                    st.session_state.polling = False
                    break
                else:
                    prog = 50
                st.progress(prog / 100, text=f"Status: {status.upper()} • Time elapsed: {elapsed}s")
        if status in ["completed", "failed"]:
            break
        time.sleep(3)

if current_page == "dashboard":
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("ZAP Proxy Status", "🟢 Running", "http://localhost:8090")
    with col2:
        st.metric("Active Modules", "12", "+ Logic Flaws & ZAP")
    with col3:
        st.metric("Manual Testing", "🟢 Enabled", "Proxy + Repeater")
    with col4:
        st.metric("Compliance", "Ready", "NIST • ISO • GDPR • PCI-DSS")
    
    st.divider()
    st.subheader("Recent Activity")
    scans = api_get("scans/") or []
    if scans:
        recent = pd.DataFrame(scans[-5:])
        st.dataframe(recent[["target", "status", "risk_score", "created_at"]], use_container_width=True)
    else:
        st.info("No scans yet. Start your first scan from the Launch Scan page.")

elif current_page == "assets":
    st.subheader("Target Assets")
    assets = api_get("assets") or []
    if st.button("➕ Add New Asset", type="primary"):
        with st.form("add_asset"):
            target = st.text_input("Target URL / IP / Domain")
            description = st.text_area("Description (optional)")
            submitted = st.form_submit_button("Add Asset")
            if submitted and target:
                api_post("assets/", {"target": target, "description": description})
                st.success("Asset added")
                st.rerun()
    if assets:
        df = pd.DataFrame(assets)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No assets configured yet.")

elif current_page == "scan":
    st.subheader("Launch Vulnerability Scan")
    assets = api_get("assets") or []
    if not assets:
        st.warning("Please add assets first.")
        st.stop()
    target = st.selectbox("Select Target", [a["target"] for a in assets])
    modules = st.multiselect(
        "Scanning Modules",
        ["subdomains", "ports", "nuclei", "headers", "tech", "dirs", "logic_flaws", "zap"],
        default=["nuclei", "logic_flaws", "zap"]
    )
    logic_checks = st.multiselect(
        "Logic Flaw Checks",
        ["idor", "bfla", "multi_account_manipulation", "price_manipulation", "mass_assignment"],
        default=["idor", "bfla"]
    )
    if st.button("🚀 Start Full Scan", type="primary", use_container_width=True):
        payload = {
            "target": target,
            "modules": modules,
            "selected_logic_checks": logic_checks
        }
        result = api_post("scans/", payload)
        if result and "id" in result:
            st.session_state.current_scan_id = result["id"]
            st.session_state.scan_start_time = time.time()
            st.session_state.polling = True
            show_live_progress(result["id"])
            st.rerun()

elif current_page == "results":
    st.subheader("Live Scan Results")
    if st.session_state.current_scan_id:
        scan = api_get(f"scans/{st.session_state.current_scan_id}")
        if scan:
            st.json(scan)
    else:
        st.info("No active scan. Launch a scan first.")

elif current_page == "history":
    st.subheader("Scan History")
    scans = api_get("scans/") or []
    if scans:
        df = pd.DataFrame(scans)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No scan history yet.")

elif current_page == "reports":
    st.subheader("Generated Reports")
    scans = api_get("scans/") or []
    for s in scans:
        col1, col2 = st.columns([4,1])
        with col1:
            st.write(f"**{s.get('target')}** • Risk: {s.get('risk_score')} • {s.get('status')}")
        with col2:
            if st.button("📄 Download PDF", key=f"pdf_{s['id']}"):
                pdf_data = api_get(f"scans/{s['id']}/report")
                if pdf_data:
                    st.download_button("Download", data=pdf_data, file_name=f"vulnora-report-{s['id']}.pdf", mime="application/pdf")

elif current_page == "compliance":
    st.subheader("Compliance Mapping")
    st.info("Vulnora maps findings automatically to global standards.")
    cols = st.columns(4)
    with cols[0]:
        st.metric("NIST SP 800-53", "Mapped", "Ready")
    with cols[1]:
        st.metric("ISO 27001", "Mapped", "Ready")
    with cols[2]:
        st.metric("GDPR", "Mapped", "Ready")
    with cols[3]:
        st.metric("PCI-DSS", "Mapped", "Ready")

elif current_page == "proxy":
    st.subheader("🛡️ Proxy Dashboard")
    status = api_get("zap/status")
    if status:
        col1, col2 = st.columns([2,1])
        with col1:
            st.success(f"**ZAP Proxy Active** • {status.get('proxy_url')}")
            st.info("Configure your browser proxy to the URL above and install the ZAP root CA for full HTTPS interception.")
        with col2:
            if st.button("🔄 Refresh Proxy Data"):
                st.rerun()
    
    tab_proxy1, tab_proxy2, tab_proxy3 = st.tabs(["Sites Tree", "HTTP History", "Alerts"])
    
    with tab_proxy1:
        sites = api_get("zap/sites") or []
        if sites:
            st.dataframe(pd.DataFrame(sites), use_container_width=True)
        else:
            st.info("No sites discovered yet. Browse through the proxy to populate.")
    
    with tab_proxy2:
        st.markdown("### Recent HTTP History")
        history = api_get("zap/history", params={"count": 100}) or []
        if history:
            df_history = pd.DataFrame(history)
            st.dataframe(df_history[["method", "url", "status", "time"]], use_container_width=True)
        else:
            st.info("No history recorded yet.")
    
    with tab_proxy3:
        alerts = api_get("zap/alerts") or []
        if alerts:
            df_alerts = pd.DataFrame(alerts)
            st.dataframe(df_alerts, use_container_width=True)
        else:
            st.info("No alerts detected yet.")

elif current_page == "repeater":
    st.subheader("🔄 Request Repeater")
    st.caption("Edit and resend requests captured from the Proxy")
    
    col_r1, col_r2 = st.columns([3,2])
    with col_r1:
        raw_request = st.text_area(
            "Raw HTTP Request",
            height=420,
            placeholder="GET /api/users HTTP/1.1\nHost: example.com\n...",
            key="repeater_raw"
        )
    with col_r2:
        st.markdown("**Repeater Controls**")
        follow_redirects = st.checkbox("Follow Redirects", value=True)
        if st.button("📤 Send Request", type="primary", use_container_width=True):
            if raw_request:
                result = api_post("zap/repeater/send", {
                    "request": raw_request,
                    "followRedirects": follow_redirects
                })
                if result:
                    st.success("Request sent successfully")
                    st.json(result)
            else:
                st.warning("Please enter a request")
    
    st.divider()
    st.caption("Tip: Copy requests directly from the Proxy History tab for quick testing and modification.")

elif current_page == "admin":
    st.subheader("Administration")
    st.info("Admin controls will appear here for user and system management.")

st.markdown("<p class='builder-credit'>built by séç gúy -cybersecurity researcher</p>", unsafe_allow_html=True)
