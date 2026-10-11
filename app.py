
from pathlib import Path
import io

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import load_logs, analyze_logs


# =========================================================
# 1. PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Cybersecurity Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# 2. PROFESSIONAL DASHBOARD THEME
# =========================================================

st.markdown("""
<style>
/* Main application background */
.stApp {
    background: linear-gradient(
        135deg,
        #F4F7FC 0%,
        #EAF1FA 100%
    );
    color: #172B4D;
}

/* Main title */
.stApp h1 {
    color: #15345B !important;
    font-weight: 800 !important;
    letter-spacing: -0.5px;
}

/* Section headings */
.stApp h2,
.stApp h3 {
    color: #183B63 !important;
    font-weight: 700 !important;
}

/* Normal text */
.stApp p,
.stApp label,
.stApp [data-testid="stMarkdownContainer"] {
    color: #334863;
}

/* Sidebar background */
section[data-testid="stSidebar"] {
    background: linear-gradient(
        180deg,
        #14243B 0%,
        #0D192B 100%
    );
    border-right: 1px solid #263A55;
}

/* Sidebar text */
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] span {
    color: #F1F5FB !important;
}

/* Sidebar info box */
section[data-testid="stSidebar"] [data-testid="stAlert"] {
    background-color: #233D5E;
    border: 1px solid #34577D;
    border-radius: 12px;
}

/* Summary metric cards */
div[data-testid="stMetric"] {
    background: #FFFFFF;
    border: 1px solid #DCE6F2;
    border-radius: 14px;
    padding: 18px;
    box-shadow: 0 4px 14px rgba(25, 55, 90, 0.05);
}

/* Metric labels */
div[data-testid="stMetricLabel"] p {
    color: #50647F !important;
    font-size: 14px;
}

/* Metric values */
div[data-testid="stMetricValue"] {
    color: #173B65 !important;
    font-weight: 750;
}

/* File uploader */
div[data-testid="stFileUploader"] {
    background-color: #FFFFFF;
    border: 1px solid #DCE6F2;
    border-radius: 12px;
    padding: 12px;
}

div[data-testid="stFileUploader"] p {
    color: #334863 !important;
}

/* Data tables */
div[data-testid="stDataFrame"] {
    background-color: #FFFFFF;
    border: 1px solid #DCE6F2;
    border-radius: 10px;
    overflow: hidden;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button {
    background-color: #173B65;
    color: #FFFFFF !important;
    border: 1px solid #173B65;
    border-radius: 9px;
    font-weight: 600;
    transition: all 0.2s ease;
}

/* Button hover */
.stButton > button:hover,
.stDownloadButton > button:hover {
    background-color: #24568B;
    color: #FFFFFF !important;
    border-color: #24568B;
}

/* Sidebar sliders */
section[data-testid="stSidebar"] [data-testid="stSlider"] {
    color: #F1F5FB;
}

/* Alerts */
div[data-testid="stAlert"] {
    border-radius: 10px;
}

/* Dividers */
hr {
    border-color: #DCE6F2;
}

/* Caption */
.stApp [data-testid="stCaptionContainer"] {
    color: #64748B;
}

/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# 3. HEADER
# =========================================================

st.title("🛡️ Cybersecurity Log Analyzer")

st.markdown(
    "Analyze login records, identify suspicious activity, "
    "and generate security reports."
)

st.caption(
    "Python-based security monitoring and log analysis dashboard"
)


# =========================================================
# 4. SIDEBAR SETTINGS
# =========================================================

st.sidebar.title("Detection Settings")

st.sidebar.markdown(
    "Configure the rules used to identify suspicious login activity."
)

threshold = st.sidebar.slider(
    "Failed attempts to trigger an alert",
    min_value=3,
    max_value=10,
    value=5,
    step=1
)

window_minutes = st.sidebar.slider(
    "Detection time window (minutes)",
    min_value=5,
    max_value=60,
    value=10,
    step=5
)

st.sidebar.divider()

st.sidebar.info(
    "Alerts indicate suspicious patterns. "
    "Investigate each alert before concluding that an attack occurred."
)

st.sidebar.caption(
    "Cybersecurity Log Analyzer | TYIT Mini Project"
)


# =========================================================
# 5. UPLOAD LOG DATASET
# =========================================================

st.header("1. Upload Log Dataset")

uploaded_file = st.file_uploader(
    "Upload a CSV file containing login records",
    type=["csv"],
    help=(
        "Required columns: timestamp, ip, username, "
        "event, details"
    )
)

if uploaded_file is None:
    source = Path(__file__).parent / "sample_logs.csv"
    source_name = "sample_logs.csv"

    st.info(
        "Using the included sample dataset. "
        "Upload your own CSV to analyze different logs."
    )
else:
    source = uploaded_file
    source_name = uploaded_file.name


# =========================================================
# 6. LOAD AND ANALYZE DATA
# =========================================================

try:
    logs = load_logs(source)

    if logs.empty:
        st.warning(
            "No valid log records were found. "
            "Please check your CSV file."
        )
        st.stop()

    results = analyze_logs(
        logs,
        threshold=threshold,
        window_minutes=window_minutes
    )

except Exception as error:
    st.error(f"Unable to analyze the dataset: {error}")
    st.stop()


st.success(
    f"Successfully loaded {len(logs)} valid records "
    f"from {source_name}"
)


# =========================================================
# 7. SECURITY OVERVIEW
# =========================================================

st.header("2. Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    results["total_events"]
)

col2.metric(
    "Failed Logins",
    results["failed_count"]
)

col3.metric(
    "Successful Logins",
    results["success_count"]
)

col4.metric(
    "Unique IP Addresses",
    results["unique_ips"]
)


# =========================================================
# 8. SECURITY ALERTS
# =========================================================

st.header("3. Security Alerts")

alerts = results["alerts"]

if alerts.empty:
    st.success(
        "No suspicious patterns were detected "
        "using the current settings."
    )

else:
    high_alerts = int(
        (alerts["severity"] == "HIGH").sum()
    )

    st.warning(
        f"{len(alerts)} alert(s) detected, "
        f"including {high_alerts} high-severity alert(s)."
    )

    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True
    )

    alerts_csv = alerts.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="Download Security Alerts CSV",
        data=alerts_csv,
        file_name="security_alerts.csv",
        mime="text/csv"
    )


# =========================================================
# 9. LOGIN ACTIVITY CHART
# =========================================================

st.header("4. Login Activity")

chart_data = pd.DataFrame({
    "Event Type": [
        "Failed Login",
        "Successful Login"
    ],
    "Count": [
        results["failed_count"],
        results["success_count"]
    ]
})

fig_login = px.bar(
    chart_data,
    x="Event Type",
    y="Count",
    color="Event Type",
    text="Count",
    title="Successful vs Failed Login Attempts",
    color_discrete_map={
        "Failed Login": "#EF5965",
        "Successful Login": "#37A879"
    }
)

fig_login.update_layout(
    plot_bgcolor="#FFFFFF",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(
        family="Arial",
        color="#334863",
        size=12
    ),
    title_font=dict(
        color="#183B63",
        size=18
    ),
    showlegend=False,
    margin=dict(l=20, r=20, t=60, b=20)
)

fig_login.update_traces(
    textposition="outside",
    marker_line_width=0
)

st.plotly_chart(
    fig_login,
    use_container_width=True
)


# =========================================================
# 10. IP ADDRESS ANALYSIS
# =========================================================

st.header("5. IP Address Analysis")

ip_summary = results["ip_summary"]

st.dataframe(
    ip_summary,
    use_container_width=True,
    hide_index=True
)

if not ip_summary.empty:
    ip_chart_data = ip_summary.sort_values(
        "failed_attempts",
        ascending=True
    )

    fig_ip = px.bar(
        ip_chart_data,
        x="failed_attempts",
        y="ip",
        orientation="h",
        text="failed_attempts",
        title="Failed Login Attempts by IP Address",
        labels={
            "ip": "IP Address",
            "failed_attempts": "Failed Attempts"
        },
        color="failed_attempts",
        color_continuous_scale=[
            "#B9D9F7",
            "#3983E6",
            "#173B65"
        ]
    )

    fig_ip.update_layout(
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Arial",
            color="#334863"
        ),
        title_font=dict(
            color="#183B63",
            size=18
        ),
        coloraxis_showscale=False,
        margin=dict(l=20, r=20, t=60, b=20)
    )

    st.plotly_chart(
        fig_ip,
        use_container_width=True
    )


# =========================================================
# 11. EVENT TIMELINE
# =========================================================

st.header("6. Event Timeline")

timeline = results["timeline"]

if not timeline.empty:
    fig_timeline = px.bar(
        timeline,
        x="date",
        y="count",
        color="event",
        barmode="group",
        title="Login Events Over Time",
        labels={
            "date": "Date",
            "count": "Number of Events",
            "event": "Event Type"
        },
        color_discrete_map={
            "LOGIN_FAILED": "#EF5965",
            "FAILED_LOGIN": "#EF5965",
            "LOGIN_FAILURE": "#EF5965",
            "AUTH_FAILURE": "#EF5965",
            "LOGIN_SUCCESS": "#37A879",
            "SUCCESSFUL_LOGIN": "#37A879",
            "AUTH_SUCCESS": "#37A879"
        }
    )

    fig_timeline.update_layout(
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Arial",
            color="#334863"
        ),
        title_font=dict(
            color="#183B63",
            size=18
        ),
        margin=dict(l=20, r=20, t=60, b=20)
    )

    st.plotly_chart(
        fig_timeline,
        use_container_width=True
    )

else:
    st.info("No timeline data is available.")


# =========================================================
# 12. COMPLETE LOG RECORDS
# =========================================================

st.header("7. Complete Log Records")

st.dataframe(
    results["cleaned_logs"],
    use_container_width=True,
    hide_index=True
)

logs_csv = results["cleaned_logs"].to_csv(
    index=False
).encode("utf-8")

st.download_button(
    label="Download Analyzed Logs CSV",
    data=logs_csv,
    file_name="analyzed_logs.csv",
    mime="text/csv"
)


# =========================================================
# 13. DOWNLOADABLE SECURITY REPORT
# =========================================================

st.header("8. Download Security Report")

report = io.StringIO()

report.write("CYBERSECURITY LOG ANALYZER REPORT\n")
report.write("=" * 40 + "\n\n")

report.write(f"Dataset: {source_name}\n")
report.write(
    f"Total events: {results['total_events']}\n"
)
report.write(
    f"Failed logins: {results['failed_count']}\n"
)
report.write(
    f"Successful logins: {results['success_count']}\n"
)
report.write(
    f"Unique IP addresses: {results['unique_ips']}\n"
)
report.write(
    f"Security alerts: {len(alerts)}\n"
)
report.write(
    f"Brute-force threshold: {threshold}\n"
)
report.write(
    f"Detection window: {window_minutes} minutes\n\n"
)

report.write("SECURITY ALERT DETAILS\n")
report.write("-" * 40 + "\n")

if alerts.empty:
    report.write("No alerts detected by the configured rules.\n")
else:
    report.write(
        alerts.to_string(index=False)
    )
    report.write("\n")

report.write(
    "\nNote: Alerts are rule-based indicators and do not "
    "confirm malicious activity.\n"
)

st.download_button(
    label="Download Text Security Report",
    data=report.getvalue(),
    file_name="security_report.txt",
    mime="text/plain"
)


# =========================================================
# 14. FOOTER
# =========================================================

st.divider()

st.caption(
    "Cybersecurity Log Analyzer | Python • Pandas • "
    "Streamlit • Plotly"
)

st.caption(
    "Educational prototype. It analyzes uploaded log data "
    "and does not block attacks or monitor a live network."
)
