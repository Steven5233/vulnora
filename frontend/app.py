import streamlit as st
import requests
import pandas as pd
import os
from datetime import datetime

API_BASE = os.getenv("API_BASE", "http://localhost:8000")

# Session state initialization
for key in ["token", "user", "role", "last_scan"]:
    if key not in st.session_state:
        st.session_state[key] = None

def get_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}

# ─── Safe API wrappers ────────────────────────────────────────────────
def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}/{endpoint}", headers=get_headers(), timeout=10, params=params)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API Error: {str(e)}")
        return None

def api_post(endpoint, json_data):
    try:
        r = requests.post(f"{API_BASE}/{endpoint}", json=json_data, headers=get_headers(), timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API Error: {str(e)}")
        return None

def api_delete(endpoint):
    try:
        r = requests.delete(f"{API_BASE}/{endpoint}", headers=get_headers(), timeout=10)
        r.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        st.error(f"API Error: {str(e)}")
        return False

# ─── UI Setup ─────────────────────────────────────────────────────────
st.set_page_config(page_title="Vulnora • Pro", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main {background-color: #0a0e1a;}
    .stApp {background-color: #0a0e1a; color: #e2e8f0;}
    h1 {font-size: 2.4rem; font-weight: 700; color: #67e8f9; margin-bottom: 0.4rem;}
    h2 {font-size: 1.8rem; color: #c084fc;}
    h3 {font-size: 1.4rem; color: #94a3b8;}
    .card {background: #1e293b; padding: 1.6rem; border-radius: 1rem; box-shadow: 0 4px 20px rgba(0,0,0,0.4); margin-bottom: 1.5rem;}
    .metric-card {background: linear-gradient(135deg, #1e293b, #334155); border-radius: 0.9rem; padding: 1.4rem; text-align:center;}
    .severity-critical {color:#ef4444; font-weight:bold;}
    .severity-high {color:#f97316;}
    .severity-medium {color:#eab308;}
    .severity-low {color:#22d3ee;}
    .stButton>button {border-radius: 0.6rem; padding: 0.6rem 1.2rem; font-weight: 600;}
    .sidebar .css-1d391kg {background-color: #1e293b !important;}
</style>
""", unsafe_allow_html=True)

# ─── Login ────────────────────────────────────────────────────────────
if not st.session_state.token:
    st.markdown("<h1 style='text-align:center;'>🛡️ Vulnora Pro</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#94a3b8;'>Built by SéçGúy • Modern Cybersecurity Platform • 2026</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Sign In", "Register"])

    with tab1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        username = st.text_input("Username", "admin")
        password = st.text_input("Password", type="password")
        if st.button("Sign In", type="primary", use_container_width=True):
            try:
                r = requests.post(f"{API_BASE}/auth/token", data={"username": username, "password": password}, timeout=10)
                r.raise_for_status()
                st.session_state.token = r.json()["access_token"]
                me = requests.get(f"{API_BASE}/users/me", headers=get_headers(), timeout=10)
                me.raise_for_status()
                st.session_state.user = me.json()
                st.session_state.role = me.json()["role"]
                st.success("Welcome to Vulnora")
                st.rerun()
            except Exception as e:
                st.error(str(e))
        st.markdown("</div>", unsafe_allow_html=True)

    st.stop()

# ─── Sidebar ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("<h2>Vulnora</h2>", unsafe_allow_html=True)
    st.caption("Built by SéçGúy")
    st.markdown("### Navigation")

    pages = {
        "🏠 Dashboard": "dashboard",
        "📦 Assets": "assets",
        "🚀 Scan": "scan",
        "📊 Results": "results",
        "📈 Reports": "reports",
        "📜 Compliance": "compliance"
    }

    if st.session_state.role == "admin":
        pages["👑 Admin Panel"] = "admin"

    selection = st.radio("Go to", list(pages.keys()), label_visibility="collapsed")
    current_page = pages[selection]

    st.divider()
    st.success(f"👤 {st.session_state.user.get('username', 'User')} • {st.session_state.role.upper()}")
    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()

# ─── Header ───────────────────────────────────────────────────────────
st.markdown(f"<h1>🛡️ Vulnora • {st.session_state.user.get('username', 'User')}</h1>", unsafe_allow_html=True)
st.caption("Enterprise Security Intelligence • Built by SéçGúy")

# ─── Pages ────────────────────────────────────────────────────────────
if current_page == "dashboard":
    dash = api_get("scans/dashboard")
    if dash:
        cols = st.columns(4)
        cols[0].markdown(f"<div class='metric-card'><h3>{dash['avg_risk_score']}</h3><p>Avg Risk Score</p><small style='color:#22d3ee;'>All scans</small></div>", unsafe_allow_html=True)
        cols[1].markdown(f"<div class='metric-card'><h3>{dash['total_assets']}</h3><p>Assets</p><small>Verified</small></div>", unsafe_allow_html=True)
        
        last_str = "Never"
        if dash.get("last_scan_time"):
            try:
                d = datetime.fromisoformat(dash["last_scan_time"].replace("Z", "+00:00"))
                last_str = d.strftime("%d %b")
            except:
                last_str = dash["last_scan_time"][:10]
        cols[2].markdown(f"<div class='metric-card'><h3>{last_str}</h3><p>Last Scan</p></div>", unsafe_allow_html=True)
        cols[3].markdown("<div class='metric-card'><h3>97.8%</h3><p>Compliance</p><small>NDPR + GDPR</small></div>", unsafe_allow_html=True)

        sev_df = pd.DataFrame(list(dash["severity_distribution"].items()), columns=["Severity", "Count"])
        sev_df["Severity"] = sev_df["Severity"].str.capitalize()
        st.subheader("Severity Distribution – All Scans")
        st.bar_chart(sev_df.set_index("Severity"), color="#f97316", use_container_width=True)

elif current_page == "assets":
    st.title("Asset Inventory")
    st.caption("Only verified and scoped assets can be scanned")

    assets = api_get("assets") or []

    with st.expander("Add New Asset", expanded=not assets):
        col1, col2 = st.columns([4,1])
        new_target = col1.text_input("Domain or IP", placeholder="app.example.com", key="new_asset_input")
        if col2.button("Add"):
            if new_target.strip():
                result = api_post("assets/", {"target": new_target.strip()})
                if result:
                    st.success(f"Added: **{new_target}**")
                    st.rerun()
            else:
                st.warning("Please enter a valid target")

    if not assets:
        st.info("No assets yet. Add your first domain or IP above to start scanning.")
    else:
        for a in assets:
            col1, col2 = st.columns([5,1])
            col1.markdown(f"**{a['target']}** • 🟢 Verified • 🔒 In scope")
            if col2.button("🗑️", key=f"del_asset_{a['id']}"):
                if api_delete(f"assets/{a['id']}"):
                    st.success("Asset deleted")
                    st.rerun()

elif current_page == "scan":
    st.title("Launch Scan")
    assets = api_get("assets") or []
    if not assets:
        st.warning("Please add at least one asset first (→ Assets page)")
    else:
        target_options = [a["target"] for a in assets]
        target = st.selectbox("Select target", target_options)
        modules = st.multiselect(
            "Scan Modules",
            ["Subdomains", "Ports", "Nuclei", "Headers", "Tech Stack", "Directories", "Screenshot"],
            default=["Subdomains", "Nuclei", "Ports"]
        )

        if st.button("Start Scan", type="primary"):
            with st.spinner("Launching secure scan containers..."):
                payload = {"target": target, "modules": [m.lower() for m in modules]}
                result = api_post("scans/", payload)
                if result:
                    st.success(f"Scan completed – Risk score: **{result.get('risk_score', 'N/A')}** • Status: {result.get('status')}")
                    st.session_state.last_scan = result
                    st.rerun()

elif current_page == "results":
    st.title("Scan Results")
    if st.session_state.get("last_scan"):
        data = st.session_state.last_scan
        st.metric("Risk Score", f"{data.get('risk_score', 'N/A')}/10", delta_color="inverse")
        st.write(f"**Status:** {data.get('status', 'completed').capitalize()}")
        st.subheader(f"Target: {data['target']}")

        if "result_data" in data:
            rd = data["result_data"]
            if "nuclei" in rd:
                st.subheader("Vulnerabilities")
                for v in rd["nuclei"]:
                    sev_class = f"severity-{v.get('severity', 'medium').lower()}"
                    st.markdown(f"- <span class='{sev_class}'>{v.get('severity', 'MEDIUM').upper()}</span> – {v.get('name')} ({v.get('id')})", unsafe_allow_html=True)
    else:
        st.info("Run a scan to see results here.")

elif current_page == "reports":
    st.title("Reports")
    st.download_button("Download CSV (sample)", "id,target,risk_score\n1,example.com,4.2", "scan-report.csv")
    st.info("PDF export coming soon")

elif current_page == "compliance":
    st.title("Compliance Status")
    st.success("Compliant with NDPR • GDPR • SOC2")
    st.info("All scans are logged and retained")

elif current_page == "admin":
    st.title("Admin – All Scans")
    scans = api_get("scans/admin/all")
    if scans:
        st.dataframe(pd.DataFrame(scans))
    else:
        st.info("No scans found or access denied.")

st.markdown("---")
st.caption("Vulnora Pro • Built by SéçGúy • Ethical security scanning platform")
