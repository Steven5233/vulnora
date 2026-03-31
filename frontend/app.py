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
    st.markdown("<h1 style='text-align:center;'>🛡️ Vulnora</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#94a3b8; font-size:1.1rem;'>Real Vulnerability Scanner for Ethical Hacking & Global GRC</p>", unsafe_allow_html=True)
    
    # Builder credit on login screen
    st.markdown("<p class='builder-credit'>Built by Cybersecurity Researcher — séç gúy</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔑 Sign In", "📝 Register"])
    
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
    st.markdown("### 🛡️ Vulnora")
    st.caption("Real Vulnerability Scanner • Ethical Hacking & Global GRC")
    
    # Professional builder credit in sidebar
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
    st.success(f"👤 {st.session_state.user.get('username')} • {st.session_state.role.upper()}")
    if st.button("Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

# ==================== MAIN HEADER ====================
st.markdown(f"<h1>🛡️ Vulnora • {st.session_state.user.get('username')}</h1>", unsafe_allow_html=True)
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
            st.markdown("### 🔄 Scan in Progress")
            if status == "pending":
                st.info("Queued... Waiting for worker")
                prog = 10
            elif status == "running":
                st.warning(f"Scanning {scan['target']}... (Elapsed: {elapsed}s)")
                prog = min(30 + (elapsed % 60), 85)
            elif status == "completed":
                st.success(f"✅ Scan Completed! Risk Score: **{risk}**/10")
                st.session_state.polling = False
                st.session_state.current_scan_id = scan_id
                break
            elif status == "failed":
                st.error("❌ Scan Failed")
                st.session_state.polling = False
                break
            else:
                prog = 50

            st.progress(prog / 100, text=f"Status: {status.upper()} • Time: {elapsed}s")

        if status in ["completed", "failed"]:
            break
        time.sleep(3)

# ==================== PAGES ====================

if current_page == "dashboard":
    dash = api_get("scans/dashboard") or {}
    cols = st.columns(4)
    cols[0].metric("Avg Risk Score", dash.get("avg_risk_score", 0))
    cols[1].metric("Assets", dash.get("total_assets", 0))
    cols[2].metric("Last Scan", dash.get("last_scan_time", "Never")[:10] if dash.get("last_scan_time") else "Never")
    cols[3].metric("Compliance", "98%")

    if dash.get("severity_distribution"):
        df = pd.DataFrame(list(dash["severity_distribution"].items()), columns=["Severity", "Count"])
        st.bar_chart(df.set_index("Severity"))

elif current_page == "assets":
    st.subheader("Asset Inventory")
    assets = api_get("assets") or []
    with st.expander("Add New Asset"):
        target = st.text_input("Domain / IP")
        if st.button("Add"):
            if target:
                if api_post("assets/", {"target": target.strip()}):
                    st.success("Asset added")
                    st.rerun()

    for a in assets:
        col1, col2 = st.columns([5,1])
        col1.write(f"**{a['target']}**")
        if col2.button("Delete", key=f"del{a['id']}"):
            if api_delete(f"assets/{a['id']}"):
                st.success("Deleted")
                st.rerun()

elif current_page == "scan":
    st.subheader("🚀 Launch Vulnerability Scan")
    assets = api_get("assets") or []
    if not assets:
        st.warning("Add assets first.")
        st.stop()

    target = st.selectbox("Target", [a["target"] for a in assets])
    modules = st.multiselect("Modules", ["subdomains", "ports", "nuclei", "headers", "tech", "dirs"], default=["nuclei", "ports", "subdomains"])

    if st.button("Start Scan", type="primary", use_container_width=True):
        result = api_post("scans/", {"target": target, "modules": modules})
        if result:
            st.session_state.current_scan_id = result["id"]
            st.session_state.scan_start_time = time.time()
            st.session_state.polling = True
            st.toast("Scan started successfully!", icon="🚀")
            st.rerun()

    if st.session_state.get("polling") and st.session_state.current_scan_id:
        show_live_progress(st.session_state.current_scan_id)

elif current_page == "results":
    st.subheader("Live Scan Results")
    scan_id = st.session_state.get("current_scan_id")
    if not scan_id:
        st.info("No recent scan. Launch one from the Scan page.")
    else:
        scan = api_get(f"scans/{scan_id}")
        if scan:
            st.metric("Risk Score", f"{scan.get('risk_score', 0)} / 10")
            data = scan.get("result_data", {}) or {}
            nuclei = data.get("nuclei", [])

            st.subheader("Findings")
            for f in nuclei:
                sev = f.get("severity", "medium")
                with st.expander(f"[{sev.upper()}] {f.get('name')}"):
                    st.markdown(f"**ID:** {f.get('id')}")
                    st.markdown(f"**Description:** {f.get('description','N/A')}")
                    st.markdown(f"**Remediation:** {f.get('remediation','N/A')}")
                    st.markdown(f"<span class='severity-{sev}'>Severity: {sev.upper()}</span>", unsafe_allow_html=True)

            if nuclei:
                if st.button("Export Findings as JSON"):
                    st.download_button("Download JSON", data=json.dumps(nuclei, indent=2), file_name=f"findings-{scan['target']}.json", mime="application/json")

elif current_page == "history":
    st.subheader("Scan History")
    scans = api_get("scans/") or []
    if scans:
        df = pd.DataFrame(scans)
        df["time"] = pd.to_datetime(df["time"]).dt.strftime("%Y-%m-%d %H:%M")
        df_display = df[["id", "target", "time", "risk_score", "status"]]
        st.dataframe(df_display, use_container_width=True, hide_index=True)

        if st.button("Export History as CSV"):
            csv = df.to_csv(index=False)
            st.download_button("Download CSV", csv, "scan_history.csv", "text/csv")
    else:
        st.info("No scans performed yet.")

elif current_page == "reports":
    st.subheader("📄 Reports")
    scans = api_get("scans/") or []
    for scan in [s for s in scans if s.get("status") == "completed"]:
        col1, col2 = st.columns([4, 2])
        col1.write(f"**{scan['target']}** — {scan['time'][:10]} (Risk: {scan.get('risk_score')})")
        if col2.button("Download PDF Report", key=f"pdf_{scan['id']}"):
            report = api_get(f"scans/{scan['id']}/report")
            if report:
                st.download_button("⬇️ Save PDF", bytes.fromhex(report["content"]), report["filename"], "application/pdf")

elif current_page == "compliance":
    st.subheader("🌍 Global Compliance Mapping")
    st.info("Findings are automatically mapped to ISO 27001, NIST CSF, GDPR, PCI DSS, SOC 2, and CIS Controls.")

elif current_page == "admin" and st.session_state.role == "admin":
    st.subheader("Admin Panel")
    all_scans = api_get("scans/admin/all") or []
    st.write(f"Total system scans: {len(all_scans)}")
    st.dataframe(pd.DataFrame(all_scans))

# Auto-refresh for live polling
if st.session_state.get("polling"):
    time.sleep(3)
    st.rerun()
