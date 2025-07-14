import streamlit as st
from streamlit_autorefresh import st_autorefresh 
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import numpy as np
import plotly.graph_objects as go
from datetime import datetime, timedelta
from plotly.subplots import make_subplots
import time as time_module
from datetime import time

import pytz
import sqlite3, pathlib, os, io, base64,getpass, platform, socket, sys

#auto refresh
# st_autorefresh(interval=1000, key="auto_refresh") 

# --- Setup ---
BASE_DIR = pathlib.Path().absolute()
DB_PATH = str(BASE_DIR / "access_logs.db")
ASSETS = BASE_DIR / "assets"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
DARK_BG = "#0e1117"
THEME_COLOR = "#4ba3c7"
THEME_ACCENT = "#ffe082"
THEME_FONT = "'Segoe UI', 'Roboto', 'Arial', sans-serif"
sns.set_theme(style="whitegrid", palette="viridis")
plt.style.use("ggplot")
plt.rcParams["figure.figsize"] = (12, 6)
plt.rcParams["font.size"] = 15
plt.rcParams["axes.facecolor"] = DARK_BG
plt.rcParams["figure.facecolor"] = DARK_BG

def _run_sql(query: str, **kw) -> pd.DataFrame:
    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query(query, conn, **kw)

def get_csv_download_link(df, filename):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    return f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download CSV</a>'

def _bounds(table: str, column: str):
    q = f"SELECT MIN({column}) AS min_t, MAX({column}) AS max_t FROM {table}"
    df = _run_sql(q)
    if df.empty or df.isnull().any(axis=None):
        return None, None
    return pd.to_datetime(df.min_t[0]), pd.to_datetime(df.max_t[0])

LOG_MIN, LOG_MAX = _bounds("logs", "time")
SUS_MIN, SUS_MAX = _bounds("ip_suspicious", "time")
BLK_MIN, BLK_MAX = _bounds("blocked_log", "backend_blocked_at")
ADV_MIN, ADV_MAX = _bounds("advanced_logs", "first_time_of_access")
DDOS_MIN, DDOS_MAX = _bounds("ddos_multiple_ip", "window_start")

GLOBAL_MIN = min(ts for ts in (LOG_MIN, SUS_MIN, BLK_MIN, ADV_MIN, DDOS_MIN) if ts is not None)
GLOBAL_MAX = max(ts for ts in (LOG_MAX, SUS_MAX, BLK_MAX, ADV_MAX, DDOS_MAX) if ts is not None)

def get_bounds(col):
    df = _run_sql(f"SELECT MIN({col}) as min_t, MAX({col}) as max_t FROM logs")
    if df.empty or df.isnull().any(axis=None):
        now = datetime.datetime.now().astimezone()
        return now, now
    return pd.to_datetime(df.iloc[0]["min_t"]), pd.to_datetime(df.iloc[0]["max_t"])

LOG_MIN, LOG_MAX = get_bounds("time")
ING_MIN, ING_MAX = get_bounds("ingest_ts")

# --- Sidebar: Logo, time spans, theme ---
with st.sidebar:
    st.image(str(ASSETS / "BlueGuardLogo.jpg"), use_container_width=True)
    st.markdown("### Dataset Time Spans")
    st.write(f"**Log time:** {LOG_MIN.date()} → {LOG_MAX.date()}")
    st.write(f"**Ingest time:** {ING_MIN.date()} → {ING_MAX.date()}")
    st.markdown("---")
    st.caption("Blue Guard SIEM © 2025")

# --- Moving/Animated Background and Theme ---
st.set_page_config("Blue-Guard SIEM", "🛡️", layout="wide")
st.markdown(f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
  body, .stApp {{
    background: linear-gradient(135deg, #0e1117 0%, #232b3e 100%);
    color: #f0f2f6;
    font-family: {THEME_FONT};
    font-size: 15px;
  }}
  .stApp {{
    background-image: url('https://www.transparenttextures.com/patterns/stardust.png'), linear-gradient(135deg, #0e1117 0%, #232b3e 100%);
    background-size: 400px 400px, cover;
    animation: bgmove 40s linear infinite;
  }}
  @keyframes bgmove {{
    0% {{background-position: 0 0, 0 0;}}
    100% {{background-position: 400px 400px, 100% 100%;}}
  }}
  [data-testid=stSidebar]{{background:#1a1d24!important;border-right:1px solid #2a2e36;}}
  .stMetric{{background:#1a1d24;border-radius:8px;padding:15px;border-left:4px solid {THEME_COLOR};}}
  .stDataFrame, .dataframe, .stTable {{background:#181c25 !important; color:#f0f2f6 !important; font-size: 15px;}}
  h1, h2, h3, h4, h5, h6 {{font-family:{THEME_FONT}; font-weight:700;}}
  .stButton>button {{background-color:{THEME_COLOR}; color:#181c25; border-radius:6px; font-weight:600;}}
  .stSlider>div>div>div>div {{background:{THEME_COLOR};}}
  .stSelectbox>div>div>div>div {{color:{THEME_COLOR};}}
  ::-webkit-scrollbar{{width:8px;}}::-webkit-scrollbar-track{{background:#1a1d24;}}
  ::-webkit-scrollbar-thumb{{background:{THEME_COLOR};border-radius:4px;}}
</style>
""", unsafe_allow_html=True)

tabs = st.tabs([
    "Overview", "Traffic", "Threats", "Suspicious IPs", "Blocked IPs", "Geography", "Advanced", "Report", "System"
])

all_figs = {}

# --- Overview Tab ---
with tabs[0]:
    st.title("BlueGuard SIEM – System Overview")
    logs = _run_sql("SELECT COUNT(*) as logs FROM logs").iloc[0,0]
    uips = _run_sql("SELECT COUNT(DISTINCT ip) as uips FROM logs").iloc[0,0]
    blocked = _run_sql("SELECT COUNT(*) as blocked FROM blocked_log").iloc[0,0]
    sus = _run_sql("SELECT COUNT(DISTINCT suspiciousIp) as sus FROM ip_suspicious").iloc[0,0]
    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">Key Metrics</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Log Events", f"{logs:,}")
    col2.metric("Unique IPs", f"{uips:,}")
    col3.metric("Blocked IPs", f"{blocked:,}")
    col4.metric("Suspicious IPs", f"{sus:,}")
    st.divider()

    # Block Latency Analysis
    latency_df = _run_sql("""
        SELECT detected_at, backend_blocked_at, client_blocked_at
        FROM blocked_log
        WHERE detected_at IS NOT NULL AND backend_blocked_at IS NOT NULL AND client_blocked_at IS NOT NULL
    """)
    latency_ms, backend_latency_ms = [], []
    for _, row in latency_df.iterrows():
        try:
            t1 = pd.to_datetime(row['detected_at'])
            t2 = pd.to_datetime(row['client_blocked_at'])
            t3 = pd.to_datetime(row['backend_blocked_at'])
            latency_ms.append((t2 - t1).total_seconds() * 1000)
            backend_latency_ms.append((t3 - t1).total_seconds() * 1000)
        except Exception:
            continue
    avg_latency = np.mean(latency_ms) if latency_ms else 0
    avg_backend_latency = np.mean(backend_latency_ms) if backend_latency_ms else 0
    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">Detection-to-Block Latency (ms)</div>', unsafe_allow_html=True)
    st.markdown(
        f"""
        <table style="width:100%;background:#181c25;color:#f0f2f6;">
            <tr>
                <th>Latency Type</th>
                <th>Average</th>
                <th>Minimum</th>
                <th>Maximum</th>
            </tr>
            <tr>
                <td>Detection → Backend Block</td>
                <td>{avg_backend_latency:.1f}</td>
                <td>{np.min(backend_latency_ms) if backend_latency_ms else 0:.1f}</td>
                <td>{np.max(backend_latency_ms) if backend_latency_ms else 0:.1f}</td>
            </tr>
            <tr>
                <td>Detection → Client Block</td>
                <td>{avg_latency:.1f}</td>
                <td>{np.min(latency_ms) if latency_ms else 0:.1f}</td>
                <td>{np.max(latency_ms) if latency_ms else 0:.1f}</td>
            </tr>
        </table>
        """, unsafe_allow_html=True
    )

    # Suspicious IPs per Day
    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">Suspicious IPs per Day</div>', unsafe_allow_html=True)
    days = st.slider("Days to show", 7, 60, 15, key="sus_days_overview")
    df = _run_sql(f"""
        SELECT DATE(time) AS day, COUNT(*) AS cnt
        FROM   ip_suspicious
        WHERE  DATE(time) >= DATE('now', '-{days-1} day')
        GROUP  BY day
        ORDER  BY day
    """)
    if not df.empty:
        all_days = pd.date_range(end=pd.Timestamp.today().normalize(), periods=days, freq="D")
        df = (df.set_index("day").reindex(all_days.strftime("%Y-%m-%d"), fill_value=0)
                .rename_axis("day").reset_index())
        fig, ax = plt.subplots(facecolor=DARK_BG)
        palette = sns.color_palette("pastel", len(df))
        sns.barplot(data=df, x="day", y="cnt", palette=palette, ax=ax, edgecolor="black", linewidth=.5)
        for p, val in zip(ax.patches, df["cnt"]):
            ax.text(p.get_x() + p.get_width()/2, p.get_height() + max(df["cnt"])*0.02, f"{val:,}", ha="center", va="bottom", fontsize=10, color="#f0f2f6")
        ax.set(title="Suspicious IPs per Day", xlabel="Date", ylabel="Count")
        plt.xticks(rotation=45, ha="right", color="#f0f2f6")
        plt.yticks(color="#f0f2f6")
        ax.title.set_color(THEME_COLOR)
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["suspicious_trend.png"] = fig
    st.markdown(get_csv_download_link(df, "suspicious_ips_trend.csv"), unsafe_allow_html=True)

    # Top 5 Most Active IPs
    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">Top 5 Most Active IPs</div>', unsafe_allow_html=True)
    top_ips_df = _run_sql("""
        SELECT ip, COUNT(*) as events
        FROM logs
        GROUP BY ip
        ORDER BY events DESC
        LIMIT 5
    """)
    if not top_ips_df.empty:
        st.dataframe(top_ips_df, hide_index=True)
        st.markdown(get_csv_download_link(top_ips_df, "top_active_ips.csv"), unsafe_allow_html=True)

    # Top 5 Most Blocked IPs
    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">Top 5 Most Blocked IPs</div>', unsafe_allow_html=True)
    top_blocked_df = _run_sql("""
        SELECT ip, detection_count
        FROM blocked_log
        ORDER BY detection_count DESC
        LIMIT 5
    """)
    if not top_blocked_df.empty:
        st.dataframe(top_blocked_df, hide_index=True)
        st.markdown(get_csv_download_link(top_blocked_df, "top_blocked_ips.csv"), unsafe_allow_html=True)

    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">Block Rate</div>', unsafe_allow_html=True)
    block_rate = (blocked / sus * 100) if sus else 0
    st.markdown(f"<b>Block rate:</b> <span style='color:{THEME_COLOR};font-weight:bold'>{block_rate:.1f}%</span> of suspicious IPs were blocked.", unsafe_allow_html=True)

    st.markdown('<div style="font-size:1.25em;font-weight:700;margin-top:36px;color:#4ba3c7;">System Features & Health Overview</div>', unsafe_allow_html=True)
    feature_table = pd.DataFrame([
        {"Feature": "Log Ingestion", "Description": "Real-time collection and storage of all access logs."},
        {"Feature": "Suspicious IP Detection", "Description": "Behavioral and ML-based anomaly detection for IPs."},
        {"Feature": "OS-level Blocking", "Description": "Automated firewall rules for detected threats."},
        {"Feature": "DDoS Detection", "Description": "Sliding window analysis for burst attacks."},
        {"Feature": "Country & Platform Enrichment", "Description": "GeoIP and user-agent parsing for every event."},
        {"Feature": "Advanced Analytics", "Description": "Request rates, error rates, unique URLs, method ratios."},
        {"Feature": "Interactive Visualizations", "Description": "All major trends and breakdowns in dashboard."},
        {"Feature": "Comprehensive Reporting", "Description": "One-click HTML/PDF reports and CSV exports."},
        {"Feature": "Latency Monitoring", "Description": "Tracks end-to-end and backend block latency."},
        {"Feature": "Top Offenders", "Description": "Quick access to most active and most blocked IPs."},
        {"Feature": "Downloadable Data", "Description": "All key data tables available for download."},
    ])
    st.dataframe(feature_table, hide_index=True, use_container_width=True)




#traffic
with tabs[1]:
    st.title("🌐 Traffic Patterns")
    st.markdown(
        """
        <style>
            .traffic-section {margin-top: 24px;}
            .traffic-metric {font-size: 1.25em; color: #4ba3c7; font-weight: 600;}
            .traffic-table th, .traffic-table td {padding: 6px 10px;}
            .traffic-table th {background: #232b3e; color: #ffe082;}
            .traffic-table tr:nth-child(even) {background: #191b1f;}
            .traffic-table tr:nth-child(odd) {background: #23262d;}
        </style>
        """, unsafe_allow_html=True
    )

    min_day, max_day = _run_sql("SELECT MIN(DATE(time)), MAX(DATE(time)) FROM logs").iloc[0]
    date_range = st.date_input(
        "Select date range",
        value=(pd.to_datetime(min_day), pd.to_datetime(max_day)),
        key="traffic_date_range"
    )
    start, end = date_range if isinstance(date_range, (list, tuple)) else (min_day, max_day)

    # --- Quick Traffic Metrics ---
    total_requests = _run_sql(f"SELECT COUNT(*) FROM logs WHERE DATE(time) BETWEEN '{start}' AND '{end}'").iloc[0,0]
    unique_visitors = _run_sql(f"SELECT COUNT(DISTINCT ip) FROM logs WHERE DATE(time) BETWEEN '{start}' AND '{end}'").iloc[0,0]
    avg_req_per_hour = _run_sql(f"SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM logs WHERE DATE(time) BETWEEN '{start}' AND '{end}' GROUP BY strftime('%Y-%m-%d %H', time))").iloc[0,0]

    col1, col2, col3 = st.columns(3)
    col1.markdown(f"<div class='traffic-metric'>Total Requests</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{total_requests:,}</div>", unsafe_allow_html=True)
    col2.markdown(f"<div class='traffic-metric'>Unique Visitors</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{unique_visitors:,}</div>", unsafe_allow_html=True)
    col3.markdown(f"<div class='traffic-metric'>Avg Requests/Hour</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{avg_req_per_hour:.1f}</div>", unsafe_allow_html=True)

    st.divider()

    # --- Hourly/Weekly Heatmap ---
    st.markdown("<div class='traffic-section'><b>Hourly/Weekly Heatmap</b></div>", unsafe_allow_html=True)
    df = _run_sql(f"""
        SELECT strftime('%w', time) wd, strftime('%H', time) hr, COUNT(*) cnt 
        FROM logs 
        WHERE DATE(time) BETWEEN '{start}' AND '{end}'
        GROUP BY wd, hr
    """)
    if not df.empty:
        df["wd"] = df["wd"].astype(int)
        df["hr"] = df["hr"].astype(int)
        pivot = df.pivot(index="wd", columns="hr", values="cnt").fillna(0)
        weekday_labels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
        fig, ax = plt.subplots(figsize=(14, 5), facecolor=DARK_BG)
        sns.heatmap(
            pivot, cmap="YlOrRd", linewidths=0.5,
            xticklabels=range(24), yticklabels=weekday_labels, ax=ax,
            cbar_kws={'label': 'Hits'}
        )
        plt.title("Request Heatmap: Hourly Activity by Weekday", color="w", pad=20)
        plt.ylabel("Weekday", color="w")
        plt.xlabel("Hour of Day", color="w")
        plt.xticks(color="w")
        plt.yticks(color="w")
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["traffic_heatmap.png"] = fig
    st.markdown(get_csv_download_link(df, "traffic_heatmap.csv"), unsafe_allow_html=True)

    # --- Top URLs ---
    st.markdown("<div class='traffic-section'><b>🔗 Top URLs</b></div>", unsafe_allow_html=True)
    top_n = st.slider("Top N URLs", 5, 30, 10, key="top_urls_slider")
    df = _run_sql(f"""
        SELECT url, COUNT(*) AS hits
        FROM logs
        WHERE DATE(time) BETWEEN '{start}' AND '{end}'
        GROUP BY url
        ORDER BY hits DESC
        LIMIT {top_n}
    """)
    if not df.empty:
        fig, ax = plt.subplots(figsize=(10, 0.6*len(df)+2), facecolor=DARK_BG)
        sns.barplot(data=df, y="url", x="hits", palette="viridis", ax=ax, edgecolor="black", linewidth=.5)
        for p in ax.patches:
            w = p.get_width()
            ax.text(w + df["hits"].max()*0.01, p.get_y() + p.get_height()/2, f"{int(w):,}", va="center", ha="left", color="w")
        ax.set(title=f"Most Accessed URLs (Top {top_n})", xlabel="Hits (requests)", ylabel="")
        plt.yticks(color="w")
        plt.xticks(color="w")
        ax.title.set_color("w")
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["top_urls.png"] = fig
        st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "top_urls.csv"), unsafe_allow_html=True)

    # --- HTTP Methods Breakdown ---
    st.markdown("<div class='traffic-section'><b>HTTP Methods Breakdown</b></div>", unsafe_allow_html=True)
    df = _run_sql(f"""
        SELECT method, COUNT(*) as cnt
        FROM logs
        WHERE DATE(time) BETWEEN '{start}' AND '{end}'
        GROUP BY method
        ORDER BY cnt DESC
    """)
    if not df.empty:
        fig, ax = plt.subplots(figsize=(8, 4), facecolor=DARK_BG)
        sns.barplot(data=df, x="method", y="cnt", palette="coolwarm", ax=ax, edgecolor="black", linewidth=.5)
        for p in ax.patches:
            h = p.get_height()
            ax.text(p.get_x() + p.get_width()/2, h + max(df["cnt"])*0.01, f"{int(h):,}", ha="center", va="bottom", color="w")
        ax.set(title="HTTP Methods Used", xlabel="Method", ylabel="Count")
        plt.yticks(color="w")
        plt.xticks(color="w")
        ax.title.set_color("w")
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["http_methods.png"] = fig
        st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "http_methods.csv"), unsafe_allow_html=True)

    # --- Client Platform Distribution ---
    st.markdown("<div class='traffic-section'><b>Client Platform Distribution</b></div>", unsafe_allow_html=True)
    df = _run_sql(f"""
        SELECT agent FROM logs WHERE DATE(time) BETWEEN '{start}' AND '{end}'
    """)
    if not df.empty:
        def extract_platform(ua):
            ua = ua.lower()
            if "android" in ua: return "Android"
            elif any(x in ua for x in ["iphone", "ipad", "ios"]): return "iOS"
            elif "windows" in ua: return "Windows"
            elif "mac os x" in ua: return "macOS"
            elif "linux" in ua: return "Linux"
            else: return "Other"
        df['Platform'] = df['agent'].apply(extract_platform)
        plat_counts = df['Platform'].value_counts().reset_index()
        plat_counts.columns = ['Platform', 'Count']
        fig = px.pie(
            plat_counts, names='Platform', values='Count',
            title="", hole=0.4,
            color_discrete_sequence=px.colors.sequential.Plasma_r
        )
        fig.update_layout(
            template='plotly_dark',
            showlegend=True,
            paper_bgcolor='#232b3e',
            plot_bgcolor='#232b3e'
        )
        st.plotly_chart(fig, use_container_width=True, key="platform_distribution")
        st.dataframe(plat_counts, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(plat_counts, "platform_distribution.csv"), unsafe_allow_html=True)

# --- Threats ---
with tabs[2]:
    st.title("🚨 Threats & Suspicion")
    st.markdown(
        """
        <style>
            .threats-section {margin-top: 24px;}
            .threats-metric {font-size: 1.15em; color: #e57373; font-weight: 600;}
        </style>
        """, unsafe_allow_html=True
    )

    # --- Key Suspicion Metrics ---
    total_suspicious = _run_sql("SELECT COUNT(*) FROM ip_suspicious").iloc[0,0]
    unique_suspicious = _run_sql("SELECT COUNT(DISTINCT suspiciousIp) FROM ip_suspicious").iloc[0,0]
    blocked_suspicious = _run_sql("SELECT COUNT(DISTINCT ip) FROM blocked_log").iloc[0,0]  # <-- Fixed column name
    col1, col2, col3 = st.columns(3)
    col1.markdown(f"<div class='threats-metric'>Suspicious Events</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{total_suspicious:,}</div>", unsafe_allow_html=True)
    col2.markdown(f"<div class='threats-metric'>Unique Suspicious IPs</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{unique_suspicious:,}</div>", unsafe_allow_html=True)
    col3.markdown(f"<div class='threats-metric'>Blocked Suspicious IPs</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{blocked_suspicious:,}</div>", unsafe_allow_html=True)

    st.divider()

    
    # --- Suspicious IPs by Country ---
    st.markdown("<div class='threats-section'><b>Suspicious IPs by Country</b></div>", unsafe_allow_html=True)
    days = st.slider("Days", 7, 60, 30, key="country_days")
    top_n = st.slider("Top N Countries", 5, 20, 10, key="country_topn")
    latest_day = _run_sql("SELECT DATE(MAX(time)) AS d FROM logs").iloc[0, 0]
    if latest_day:
        # Ensure latest_day is a string in ISO format (YYYY-MM-DD)
        start_day = (datetime.strptime(latest_day, "%Y-%m-%d") - timedelta(days=days)).strftime("%Y-%m-%d")
        # start_day = (datetime.fromisoformat(latest_day) - timedelta(days=days)).strftime("%Y-%m-%d")
        df = _run_sql(f"""
            SELECT l.country, COUNT(DISTINCT s.suspiciousIp) AS cnt
            FROM   ip_suspicious AS s
            JOIN   logs           AS l  ON l.ip = s.suspiciousIp
            WHERE  DATE(l.time) BETWEEN '{start_day}' AND '{latest_day}'
            GROUP  BY l.country
            ORDER  BY cnt DESC
            LIMIT  {top_n}
        """)
        if not df.empty:
            fig_map = px.choropleth(
                df,
                locations="country",
                locationmode="country names",
                color="cnt",
                color_continuous_scale="Reds",
                title="Suspicious IPs by Country",
                template="plotly_dark"
            )
            st.plotly_chart(fig_map, use_container_width=True, key="suspicious_by_country")
            all_figs["suspicious_by_country_map.png"] = fig_map
            st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "suspicious_by_country.csv"), unsafe_allow_html=True)
    # # --- Suspicious IPs by Country ---
    # st.markdown("<div class='threats-section'><b>Suspicious IPs by Country</b></div>", unsafe_allow_html=True)
    # days = st.slider("Days", 7, 60, 30, key="country_days")
    # top_n = st.slider("Top N Countries", 5, 20, 10, key="country_topn")
    # latest_day = _run_sql("SELECT DATE(MAX(time)) AS d FROM logs").iloc[0, 0]
    # if latest_day:
    #     start_day = (datetime.fromisoformat(latest_day) - timedelta(days=days)).strftime("%Y-%m-%d")
    #     df = _run_sql(f"""
    #         SELECT l.country, COUNT(DISTINCT s.suspiciousIp) AS cnt
    #         FROM   ip_suspicious AS s
    #         JOIN   logs           AS l  ON l.ip = s.suspiciousIp
    #         WHERE  DATE(l.time) BETWEEN '{start_day}' AND '{latest_day}'
    #         GROUP  BY l.country
    #         ORDER  BY cnt DESC
    #         LIMIT  {top_n}
    #     """)
    #     if not df.empty:
    #         fig_map = px.choropleth(df, locations="country", locationmode="country names",
    #                                 color="cnt", color_continuous_scale="Reds",
    #                                 title="Suspicious IPs by Country",
    #                                 template="plotly_dark")
    #         st.plotly_chart(fig_map, use_container_width=True, key="suspicious_by_country")
    #         all_figs["suspicious_by_country_map.png"] = fig_map
    #         st.dataframe(df, hide_index=True, use_container_width=True)
    # st.markdown(get_csv_download_link(df, "suspicious_by_country.csv"), unsafe_allow_html=True)

    # --- Top Suspicious IPs Table ---
    st.markdown("<div class='threats-section'><b>Top Suspicious IPs</b></div>", unsafe_allow_html=True)
    df = _run_sql(f"""
        SELECT suspiciousIp, COUNT(*) as events
        FROM ip_suspicious
        WHERE DATE(time) BETWEEN DATE('now', '-{days} day') AND DATE('now')
        GROUP BY suspiciousIp
        ORDER BY events DESC
        LIMIT 10
    """)
    if not df.empty:
        st.dataframe(df, hide_index=True, use_container_width=True)
        st.markdown(get_csv_download_link(df, "top_suspicious_ips.csv"), unsafe_allow_html=True)

    # --- Reasons for Suspicion ---
    st.markdown("<div class='threats-section'><b>Reasons for Suspicion</b></div>", unsafe_allow_html=True)
    df = _run_sql(f"""
        SELECT reason, COUNT(*) AS cnt
        FROM ip_suspicious
        WHERE DATE(time) BETWEEN DATE('now', '-{days} day') AND DATE('now')
        GROUP BY reason
        ORDER BY cnt DESC
    """)
    if not df.empty:
        fig, ax = plt.subplots(figsize=(10, 0.6*len(df)+2), facecolor=DARK_BG)
        sns.barplot(data=df, y="reason", x="cnt", palette="Reds", ax=ax, edgecolor='black', linewidth=0.5)
        for p in ax.patches:
            width = p.get_width()
            ax.text(width + max(df["cnt"]) * 0.01, p.get_y() + p.get_height() / 2, f'{int(width):,}', ha='left', va='center', color="w")
        plt.title(f"Reasons for Suspicious IPs (last {days} days)", color="w", pad=20)
        plt.xlabel("Count", color="w")
        plt.ylabel("Reason", color="w")
        plt.xticks(color="w")
        plt.yticks(color="w")
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["suspicious_reasons.png"] = fig
        st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "suspicious_reasons.csv"), unsafe_allow_html=True)

    # --- Recent Threat Timeline ---
    st.markdown("<div class='threats-section'><b>Recent Threat Timeline</b></div>", unsafe_allow_html=True)
    df = _run_sql(f"""
        SELECT suspiciousIp, reason, time
        FROM ip_suspicious
        WHERE DATE(time) BETWEEN DATE('now', '-{days} day') AND DATE('now')
        ORDER BY time DESC
        LIMIT 30
    """)
    if not df.empty:
        st.dataframe(df, hide_index=True, use_container_width=True)
        st.markdown(get_csv_download_link(df, "recent_threat_timeline.csv"), unsafe_allow_html=True)


# --- SUSPICIOUS IPs TAB ---
with tabs[3]:
    st.title("🕵️ Suspicious IPs Analysis")
    
    # Search and filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        search_ip = st.text_input("🔍 Search IP", key="susip_search")
    with col2:
        days = st.slider("📅 Days to show", 1, 30, 7, key="susip_days")
    with col3:
        reason_filter = st.selectbox("🎯 Filter by Reason", 
                                   ["All"] + list(_run_sql("SELECT DISTINCT reason FROM ip_suspicious").iloc[:,0]))
    
    # Get suspicious IPs data
    reason_condition = f"AND reason = '{reason_filter}'" if reason_filter != "All" else ""
    query = f"""
        SELECT suspiciousIp, MAX(time) as last_seen, COUNT(*) as events, 
               GROUP_CONCAT(DISTINCT reason) as reasons,
               MIN(time) as first_seen
        FROM ip_suspicious
        WHERE DATE(time) >= DATE('now', '-{days} days')
        {reason_condition}
        GROUP BY suspiciousIp
        ORDER BY events DESC
        LIMIT 100
    """
    
    df = _run_sql(query)
    
    if search_ip:
        df = df[df['suspiciousIp'].str.contains(search_ip, case=False, na=False)]
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Suspicious IPs", len(df))
    col2.metric("Total Events", df['events'].sum() if not df.empty else 0)
    col3.metric("Avg Events per IP", f"{df['events'].mean():.1f}" if not df.empty else "0")
    col4.metric("Most Active IP", df.iloc[0]['suspiciousIp'] if not df.empty else "None")
    
    # Suspicious IPs Timeline
    st.subheader("📈 Suspicious Activity Timeline")
    reason_condition = f"AND reason = '{reason_filter}'" if reason_filter != "All" else ""
    timeline_df = _run_sql(f"""
        SELECT DATE(time) as day, COUNT(*) as events,
               COUNT(DISTINCT suspiciousIp) as unique_ips
        FROM ip_suspicious
        WHERE DATE(time) >= DATE('now', '-{days} days')
        {reason_condition}
        GROUP BY DATE(time)
        ORDER BY day
    """)
    
    if not timeline_df.empty:
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        fig.add_trace(go.Bar(x=timeline_df['day'], y=timeline_df['events'], 
                            name='Events', marker_color='#ff6b6b'), secondary_y=False)
        fig.add_trace(go.Scatter(x=timeline_df['day'], y=timeline_df['unique_ips'], 
                                mode='lines+markers', name='Unique IPs', 
                                line=dict(color='#00cc88')), secondary_y=True)
        
        fig.update_layout(title="Suspicious Activity Over Time", template="plotly_dark", height=400)
        fig.update_xaxes(title_text="Date")
        fig.update_yaxes(title_text="Events", secondary_y=False)
        fig.update_yaxes(title_text="Unique IPs", secondary_y=True)
        st.plotly_chart(fig, use_container_width=True)
    
    # Threat Distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Threat Type Distribution")
        threat_dist = _run_sql(f"""
            SELECT reason, COUNT(*) as count
            FROM ip_suspicious
            WHERE DATE(time) >= DATE('now', '-{days} days')
            GROUP BY reason
            ORDER BY count DESC
        """)
        
        if not threat_dist.empty:
            fig = px.pie(threat_dist, values='count', names='reason', 
                        title="Threat Types",
                        color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_layout(template="plotly_dark", height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🔥 Top Suspicious IPs")
        top_ips = df.head(10) if not df.empty else pd.DataFrame()
        if not top_ips.empty:
            fig = px.bar(top_ips, x='events', y='suspiciousIp', 
                        orientation='h', title="Most Active Suspicious IPs",
                        color='events', color_continuous_scale='Reds')
            fig.update_layout(template="plotly_dark", height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    # Detailed table
    st.subheader("📋 Detailed Suspicious IPs")
    if not df.empty:
        st.dataframe(df, hide_index=True, use_container_width=True)
        st.markdown(get_csv_download_link(df, "suspicious_ips.csv"), unsafe_allow_html=True)
    else:
        st.info("No suspicious IPs found for the selected criteria.")

# --- BLOCKED IPs TAB ---
with tabs[4]:
    st.title("⛔ Blocked IPs Analysis")
    
    # Search and filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        search_ip = st.text_input("🔍 Search Blocked IP", key="blockip_search")
    with col2:
        days = st.slider("📅 Days to show", 1, 30, 7, key="blockip_days")
    with col3:
        status_filter = st.selectbox("🛡️ Block Status", 
                                   ["All"] + list(_run_sql("SELECT DISTINCT client_block_status FROM blocked_log WHERE client_block_status IS NOT NULL").iloc[:,0]))
    
    # Get blocked IPs data
    status_condition = f"AND client_block_status = '{status_filter}'" if status_filter != "All" else ""
    query = f"""
        SELECT ip, detected_at, backend_blocked_at, detection_count, 
               client_blocked_at, client_block_status,
               (julianday(backend_blocked_at) - julianday(detected_at)) * 24 * 60 as response_time_minutes
        FROM blocked_log
        WHERE DATE(backend_blocked_at) >= DATE('now', '-{days} days')
        {status_condition}
        ORDER BY detection_count DESC, ip
        LIMIT 100
    """
    
    df = _run_sql(query)
    
    if search_ip:
        df = df[df['ip'].str.contains(search_ip, case=False, na=False)]
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Blocked IPs", len(df))
    col2.metric("Total Detections", df['detection_count'].sum() if not df.empty else 0)
    col3.metric("Avg Detections per IP", f"{df['detection_count'].mean():.1f}" if not df.empty else "0")
    col4.metric("Most Detected IP", df.iloc[0]['ip'] if not df.empty else "None")
    
    # Blocking Timeline
    st.subheader("🚫 Blocking Activity Timeline")
    status_condition = f"AND client_block_status = '{status_filter}'" if status_filter != "All" else ""
    timeline_df = _run_sql(f"""
        SELECT DATE(backend_blocked_at) as day, COUNT(*) as blocked_count,
               SUM(detection_count) as total_detections
        FROM blocked_log
        WHERE DATE(backend_blocked_at) >= DATE('now', '-{days} days')
        {status_condition}
        GROUP BY DATE(backend_blocked_at)
        ORDER BY day
    """)
    
    if not timeline_df.empty:
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        fig.add_trace(go.Bar(x=timeline_df['day'], y=timeline_df['blocked_count'], 
                            name='Blocked IPs', marker_color='#ff4444'), secondary_y=False)
        fig.add_trace(go.Scatter(x=timeline_df['day'], y=timeline_df['total_detections'], 
                                mode='lines+markers', name='Total Detections', 
                                line=dict(color='#ffaa00')), secondary_y=True)
        
        fig.update_layout(title="Blocking Activity Over Time", template="plotly_dark", height=400)
        fig.update_xaxes(title_text="Date")
        fig.update_yaxes(title_text="Blocked IPs", secondary_y=False)
        fig.update_yaxes(title_text="Detections", secondary_y=True)
        st.plotly_chart(fig, use_container_width=True)
    
    # Analysis charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Detection Count Distribution")
        if not df.empty:
            detection_bins = pd.cut(df['detection_count'], bins=10, include_lowest=True)
            bin_counts = detection_bins.value_counts().sort_index()
            
            fig = px.bar(x=[f"{interval.left:.0f}-{interval.right:.0f}" for interval in bin_counts.index], 
                        y=bin_counts.values, 
                        title="Detection Count Distribution",
                        color=bin_counts.values, color_continuous_scale='Oranges')
            fig.update_layout(template="plotly_dark", height=300)
            fig.update_xaxes(title_text="Detection Count Range")
            fig.update_yaxes(title_text="Number of IPs")
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⏱️ Response Time Analysis")
        if not df.empty and 'response_time_minutes' in df.columns:
            response_times = df['response_time_minutes']
            response_times = response_times[response_times >= 0]  # Remove negative values
            
            if len(response_times) > 0:
                fig = px.histogram(x=response_times, nbins=20, 
                                 title="Response Time Distribution (Minutes)",
                                 color_discrete_sequence=['#66ccff'])
                fig.update_layout(template="plotly_dark", height=300)
                fig.update_xaxes(title_text="Response Time (Minutes)")
                fig.update_yaxes(title_text="Count")
                st.plotly_chart(fig, use_container_width=True)
    
    # Block Status Summary
    if not df.empty:
        st.subheader("🛡️ Block Status Summary")
        status_summary = df['client_block_status'].value_counts()
        
        col1, col2, col3 = st.columns(3)
        for i, (status, count) in enumerate(status_summary.items()):
            with [col1, col2, col3][i % 3]:
                st.metric(f"Status: {status}", count)
    
    # Detailed table
    st.subheader("📋 Detailed Blocked IPs")
    if not df.empty:
        # Format the dataframe for better display
        display_df = df.copy()
        if 'response_time_minutes' in display_df.columns:
            display_df['response_time_minutes'] = display_df['response_time_minutes'].round(2)
        
        st.dataframe(display_df, hide_index=True, use_container_width=True)
        st.markdown(get_csv_download_link(display_df, "blocked_ips.csv"), unsafe_allow_html=True)
    else:
        st.info("No blocked IPs found for the selected criteria.")


# --- Geography ---
with tabs[5]:
    # --- Date Selection ---
    # Get all unique dates from logs for user selection
    date_options = _run_sql("SELECT DISTINCT DATE(time) as day FROM logs ORDER BY day DESC")['day'].tolist()
    if date_options:
        selected_day = st.selectbox("Select date to analyze", date_options, key="geo_day_sel")
    else:
        selected_day = None

    # Adjust the page title dynamically
    if selected_day:
        st.title(f"🌍 Geography Analytics ({selected_day})")
    else:
        st.title("🌍 Geography Analytics")

    st.markdown(
        """
        <style>
            .geo-section {margin-top: 28px;}
            .geo-metric {font-size: 1.15em; color: #4ba3c7; font-weight: 600;}
            .geo-table th, .geo-table td {padding: 6px 10px;}
            .geo-table th {background: #232b3e; color: #ffe082;}
            .geo-table tr:nth-child(even) {background: #191b1f;}
            .geo-table tr:nth-child(odd) {background: #23262d;}
        </style>
        """, unsafe_allow_html=True
    )

    if selected_day:
        # --- Country Request Distribution ---
        df = _run_sql(f"""
            SELECT country, COUNT(*) AS cnt
            FROM   logs
            WHERE  DATE(time) = '{selected_day}'
            GROUP  BY country
            ORDER  BY cnt DESC
        """)

        # --- Quick Metrics ---
        total_requests = df["cnt"].sum() if not df.empty else 0
        unique_countries = df["country"].nunique() if not df.empty else 0
        top_country = df.iloc[0]["country"] if not df.empty else "N/A"
        top_country_count = df.iloc[0]["cnt"] if not df.empty else 0

        col1, col2, col3 = st.columns(3)
        col1.markdown(f"<div class='geo-metric'>Total Requests ({selected_day})</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{total_requests:,}</div>", unsafe_allow_html=True)
        col2.markdown(f"<div class='geo-metric'>Countries Active</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{unique_countries:,}</div>", unsafe_allow_html=True)
        col3.markdown(f"<div class='geo-metric'>Top Country</div><div style='font-size:2em;color:#ffe082;font-weight:700'>{top_country} ({top_country_count:,})</div>", unsafe_allow_html=True)

        st.divider()

        # --- Top 10 Countries Table ---
        st.markdown("#### Top 10 Countries by Requests")
        if not df.empty:
            top10 = df.head(10)
            st.dataframe(top10, hide_index=True, use_container_width=True)

            # --- Choropleth Map: Requests by Country ---
            fig_map = px.choropleth(
                df,
                locations="country",
                locationmode="country names",
                color="cnt",
                color_continuous_scale=[
                    "#232b3e", "#4ba3c7", "#ffe082"
                ],
                title=f"Requests by Country ({selected_day})",
                template="plotly_dark",
                labels={"cnt": "Requests"},
            )
            fig_map.update_layout(
                paper_bgcolor="#181c25",
                geo_bgcolor="#181c25",
                font_color="#f0f2f6",
                title_font_color="#4ba3c7",
                legend=dict(font=dict(color="#f0f2f6")),
                margin=dict(l=0, r=0, t=40, b=0),
                coloraxis_colorbar=dict(
                    title=dict(
                        text="Requests",
                        font=dict(color="#4ba3c7")
                    ),
                    tickfont=dict(color="#f0f2f6"),
                ),
            )
            st.plotly_chart(fig_map, use_container_width=True, key="geo_country_map")

            # --- Pie Chart: Share of Top 10 vs Rest ---
            st.markdown("<div class='geo-section'><b>Top 10 vs Rest: Request Share</b></div>", unsafe_allow_html=True)
            pie_df = top10.copy()
            rest = df.iloc[10:]["cnt"].sum()
            if rest > 0:
                pie_df = pd.concat([
                    pie_df,
                    pd.DataFrame([{"country": "Other", "cnt": rest}])
                ], ignore_index=True)

            fig_pie = px.pie(
                pie_df,
                names="country",
                values="cnt",
                title="Top 10 Countries vs Rest",
                color_discrete_sequence=px.colors.sequential.Plasma_r,
                hole=0.45
            )
            fig_pie.update_layout(
                template="plotly_dark",
                paper_bgcolor="#181c25",
                font_color="#f0f2f6",
                legend_title_text="Country"
            )
            st.plotly_chart(fig_pie, use_container_width=True, key="geo_pie_top10")

            # --- Drilldown: Select a country for daily trend ---
            st.markdown("#### Drilldown: Select a country for daily trend")
            country_sel = st.selectbox("Country", df["country"], key="geo_country_sel")
            df2 = _run_sql(f"""
                SELECT DATE(time) as day, COUNT(*) as cnt
                FROM logs
                WHERE country = '{country_sel}'
                GROUP BY day
                ORDER BY day
            """)
            if not df2.empty:
                fig, ax = plt.subplots(facecolor="#181c25")
                sns.lineplot(data=df2, x="day", y="cnt", marker="o", ax=ax, color="#4ba3c7")
                ax.set(title=f"Daily Requests for {country_sel}", xlabel="Date", ylabel="Hits")
                plt.xticks(rotation=45, ha="right", color="#f0f2f6")
                plt.yticks(color="#f0f2f6")
                ax.title.set_color("#ffe082")
                fig.tight_layout()
                st.pyplot(fig)
                all_figs[f"country_trend_{country_sel}.png"] = fig

            # --- Country-Hour Heatmap (Top 5 Countries) ---
            st.markdown("<div class='geo-section'><b>Country-Hour Heatmap (Top 5 Countries)</b></div>", unsafe_allow_html=True)
            top5 = df.head(5)["country"].tolist()
            df_heat = _run_sql(f"""
                SELECT country, strftime('%H', time) as hour, COUNT(*) as cnt
                FROM logs
                WHERE DATE(time) = '{selected_day}' AND country IN ({','.join([f"'{c}'" for c in top5])})
                GROUP BY country, hour
            """)
            if not df_heat.empty:
                df_heat["hour"] = df_heat["hour"].astype(int)
                pivot = df_heat.pivot(index="country", columns="hour", values="cnt").fillna(0)
                fig, ax = plt.subplots(figsize=(14, 2.2*len(top5)), facecolor="#181c25")
                sns.heatmap(
                    pivot,
                    cmap=sns.color_palette(["#232b3e", "#4ba3c7", "#ffe082"], as_cmap=True),
                    linewidths=0.5, ax=ax,
                    cbar_kws={'label': 'Hits'}, annot=True, fmt=".0f"
                )
                plt.title("Hourly Distribution for Top 5 Countries", color="#4ba3c7", pad=18)
                plt.xlabel("Hour of Day", color="#f0f2f6")
                plt.ylabel("Country", color="#f0f2f6")
                plt.xticks(color="#f0f2f6")
                plt.yticks(color="#f0f2f6")
                fig.tight_layout()
                st.pyplot(fig)
                all_figs["country_hour_heatmap.png"] = fig

            # --- Suspicious Activity by Country (Selected Day) ---
            st.markdown("<div class='geo-section'><b>Suspicious Activity by Country ({})</b></div>".format(selected_day), unsafe_allow_html=True)
            df_sus = _run_sql(f"""
                SELECT l.country, COUNT(*) as cnt
                FROM ip_suspicious s
                JOIN logs l ON l.ip = s.suspiciousIp
                WHERE DATE(l.time) = '{selected_day}'
                GROUP BY l.country
                ORDER BY cnt DESC
            """)
            if not df_sus.empty:
                st.dataframe(df_sus.head(10), hide_index=True, use_container_width=True)
                fig_sus = px.choropleth(
                    df_sus,
                    locations="country",
                    locationmode="country names",
                    color="cnt",
                    color_continuous_scale=[
                        "#232b3e", "#e57373", "#ffe082"
                    ],
                    title=f"Suspicious Events by Country ({selected_day})",
                    template="plotly_dark",
                    labels={"cnt": "Suspicious Events"}
                )
                fig_sus.update_layout(
                    paper_bgcolor="#181c25",
                    geo_bgcolor="#181c25",
                    font_color="#f0f2f6",
                    title_font_color="#e57373",
                    legend=dict(font=dict(color="#f0f2f6")),
                    margin=dict(l=0, r=0, t=40, b=0),
                    coloraxis_colorbar=dict(
                        title=dict(
                            text="Suspicious",
                            font=dict(color="#e57373")
                        ),
                        tickfont=dict(color="#f0f2f6"),
                    ),
                )
                st.plotly_chart(fig_sus, use_container_width=True, key="geo_suspicious_map")
                all_figs["country_suspicious_map.png"] = fig_sus

        st.markdown(get_csv_download_link(df, "country_hits.csv"), unsafe_allow_html=True)

# --- Advanced ---
with tabs[6]:
    st.title("🧠 Advanced Analytics")

    st.markdown(
        """
        <style>
            .adv-section {margin-top: 28px;}
            .adv-metric {font-size: 1.15em; color: #4ba3c7; font-weight: 600;}
            .adv-table th, .adv-table td {padding: 6px 10px;}
            .adv-table th {background: #232b3e; color: #ffe082;}
            .adv-table tr:nth-child(even) {background: #191b1f;}
            .adv-table tr:nth-child(odd) {background: #23262d;}
        </style>
        """, unsafe_allow_html=True
    )

    # --- Advanced Log Summary ---
    st.subheader("Advanced Log Summary")

    min_date, max_date = _run_sql("SELECT MIN(first_time_of_access), MAX(first_time_of_access) FROM advanced_logs").iloc[0]
    if pd.isnull(min_date) or pd.isnull(max_date):
        st.info("No advanced logs available.")
    else:
        date_options = _run_sql("SELECT DISTINCT DATE(first_time_of_access) as day FROM advanced_logs ORDER BY day DESC")['day'].tolist()
        if date_options:
            selected_dates = st.multiselect("Select dates to analyze", date_options, default=[date_options[0]], key="adv_dates_sel")
        else:
            selected_dates = []

        if selected_dates:
            df = _run_sql(f"""
                SELECT * FROM advanced_logs
                WHERE DATE(first_time_of_access) IN ({','.join([f"'{d}'" for d in selected_dates])})
                ORDER BY req_per_min DESC
                LIMIT 200
            """)
            if df.empty:
                st.info("No advanced logs for the selected dates.")
            else:
                # --- Advanced Metrics ---
                total_logs = len(df)
                unique_ips = df['ip'].nunique() if 'ip' in df.columns else 0
                max_rpm = df['req_per_min'].max() if 'req_per_min' in df.columns else 0
                avg_rpm = df['req_per_min'].mean() if 'req_per_min' in df.columns else 0

                col1, col2, col3, col4 = st.columns(4)
                col1.markdown(f"<div class='adv-metric'>Log Entries</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{total_logs:,}</div>", unsafe_allow_html=True)
                col2.markdown(f"<div class='adv-metric'>Unique IPs</div><div style='font-size:2em;color:#f0f2f6;font-weight:700'>{unique_ips:,}</div>", unsafe_allow_html=True)
                col3.markdown(f"<div class='adv-metric'>Max Req/Min</div><div style='font-size:2em;color:#ffe082;font-weight:700'>{max_rpm:,}</div>", unsafe_allow_html=True)
                col4.markdown(f"<div class='adv-metric'>Avg Req/Min</div><div style='font-size:2em;color:#4ba3c7;font-weight:700'>{avg_rpm:.1f}</div>", unsafe_allow_html=True)

                st.dataframe(df, hide_index=True, use_container_width=True)
                st.markdown(get_csv_download_link(df, "advanced_logs.csv"), unsafe_allow_html=True)

                # --- Top Offenders by Req/Min ---
                st.markdown("<div class='adv-section'><b>Top Offenders by Requests/Min</b></div>", unsafe_allow_html=True)
                # Only select columns that exist
                offender_cols = [col for col in ['ip', 'req_per_min', 'first_time_of_access', 'last_time_of_access'] if col in df.columns]
                if offender_cols:
                    top_offenders = df[offender_cols].sort_values('req_per_min', ascending=False).head(10)
                    st.dataframe(top_offenders, hide_index=True, use_container_width=True)
                else:
                    st.info("Top offender columns not found in data.")

                # --- Activity Timeline (Requests per Min Over Time) ---
                st.markdown("<div class='adv-section'><b>Requests per Minute Timeline</b></div>", unsafe_allow_html=True)
                if 'first_time_of_access' in df.columns and 'req_per_min' in df.columns:
                    timeline = df.groupby('first_time_of_access')['req_per_min'].sum().reset_index()
                    if not timeline.empty:
                        fig, ax = plt.subplots(facecolor="#181c25")
                        sns.lineplot(data=timeline, x="first_time_of_access", y="req_per_min", marker="o", ax=ax, color="#4ba3c7")
                        ax.set(title="Total Requests/Min Over Time", xlabel="Timestamp", ylabel="Requests/Min")
                        plt.xticks(rotation=45, ha="right", color="#f0f2f6")
                        plt.yticks(color="#f0f2f6")
                        ax.title.set_color("#ffe082")
                        fig.tight_layout()
                        st.pyplot(fig)

                # --- Unusual User-Agent/Platform Analysis ---
                st.markdown("<div class='adv-section'><b>Unusual User-Agents</b></div>", unsafe_allow_html=True)
                if 'user_agent' in df.columns:
                    ua_counts = df['user_agent'].value_counts().reset_index().rename(columns={'index': 'user_agent', 'user_agent': 'count'})
                    st.dataframe(ua_counts.head(10), hide_index=True, use_container_width=True)

        else:
            st.info("Please select at least one date to view advanced logs.")

    # --- DDoS Incidents ---
    st.subheader("DDoS Incidents")
    min_ddos, max_ddos = _run_sql("SELECT MIN(window_start), MAX(window_end) FROM ddos_multiple_ip").iloc[0]
    if pd.isnull(min_ddos) or pd.isnull(max_ddos):
        st.info("No DDoS incidents recorded.")
    else:
        ddos_dates = _run_sql("SELECT DISTINCT DATE(window_start) as day FROM ddos_multiple_ip ORDER BY day DESC")['day'].tolist()
        ddos_selected = st.multiselect("Select DDoS incident dates", ddos_dates, default=[ddos_dates[0]] if ddos_dates else [], key="ddos_dates_sel")
        if ddos_selected:
            df_ddos = _run_sql(f"""
                SELECT * FROM ddos_multiple_ip
                WHERE DATE(window_start) IN ({','.join([f"'{d}'" for d in ddos_selected])})
                ORDER BY window_end DESC
                LIMIT 50
            """)
            if df_ddos.empty:
                st.info("No DDoS incidents for the selected dates.")
            else:
                st.dataframe(df_ddos, hide_index=True, use_container_width=True)
                st.markdown(get_csv_download_link(df_ddos, "ddos_incidents.csv"), unsafe_allow_html=True)

                # --- DDoS Attack Timeline ---
                st.markdown("<div class='adv-section'><b>DDoS Attack Timeline</b></div>", unsafe_allow_html=True)
                if 'window_start' in df_ddos.columns and 'total_requests' in df_ddos.columns:
                    timeline = df_ddos.groupby('window_start')['total_requests'].sum().reset_index()
                    if not timeline.empty:
                        fig, ax = plt.subplots(facecolor="#181c25")
                        sns.lineplot(data=timeline, x="window_start", y="total_requests", marker="o", ax=ax, color="#e57373")
                        ax.set(title="Total Requests in DDoS Windows", xlabel="Window Start", ylabel="Requests")
                        plt.xticks(rotation=45, ha="right", color="#f0f2f6")
                        plt.yticks(color="#f0f2f6")
                        ax.title.set_color("#e57373")
                        fig.tight_layout()
                        st.pyplot(fig)

                # --- Top Targeted IPs in DDoS ---
                st.markdown("<div class='adv-section'><b>Top Targeted IPs in DDoS Incidents</b></div>", unsafe_allow_html=True)
                if 'ip' in df_ddos.columns:
                    top_targets = df_ddos['ip'].value_counts().reset_index().rename(columns={'index': 'ip', 'ip': 'count'})
                    st.dataframe(top_targets.head(10), hide_index=True, use_container_width=True)
        else:
            st.info("Please select at least one date to view DDoS incidents.")

# --- Reports Tab ---
def get_latest_platform_pie(static_dir):
    pngs = sorted(static_dir.glob("platform_pie_day_*.png"), reverse=True)
    return pngs[0] if pngs else None

def create_hourly_activity_analysis(df_hourly):
    """Create comprehensive hourly activity analysis"""
    analysis = []
    peak_hours = df_hourly.nlargest(3, 'requests')['hour'].tolist()
    low_hours = df_hourly.nsmallest(3, 'requests')['hour'].tolist()
    analysis.append(f"Peak activity hours: {', '.join(map(str, peak_hours))}")
    analysis.append(f"Low activity hours: {', '.join(map(str, low_hours))}")
    business_hours = df_hourly[(df_hourly['hour'] >= 9) & (df_hourly['hour'] <= 17)]
    after_hours = df_hourly[(df_hourly['hour'] < 9) | (df_hourly['hour'] > 17)]
    business_total = business_hours['requests'].sum()
    after_hours_total = after_hours['requests'].sum()
    analysis.append(f"Business hours (9-17): {business_total:,} requests ({business_total/(business_total+after_hours_total)*100:.1f}%)")
    analysis.append(f"After hours: {after_hours_total:,} requests ({after_hours_total/(business_total+after_hours_total)*100:.1f}%)")
    return analysis

def create_threat_analysis(sus_df, blocked_df):
    """Create threat landscape analysis"""
    analysis = []
    total_suspicious = len(sus_df)
    total_blocked = len(blocked_df)
    analysis.append(f"Total suspicious events: {total_suspicious:,}")
    analysis.append(f"Total blocked IPs: {total_blocked:,}")
    if not sus_df.empty:
        top_reasons = sus_df['reason'].value_counts().head(3)
        analysis.append(f"Top threat types: {', '.join(top_reasons.index.tolist())}")
    if total_suspicious > 0:
        block_rate = (total_blocked / total_suspicious) * 100
        analysis.append(f"Block rate: {block_rate:.1f}% of suspicious IPs were blocked")
    return analysis

def create_geographical_analysis(country_df):
    """Create geographical threat analysis"""
    analysis = []
    if not country_df.empty:
        total_countries = len(country_df)
        top_country = country_df.iloc[0]
        analysis.append(f"Traffic from {total_countries} countries")
        analysis.append(f"Top country: {top_country['country']} ({top_country['requests']:,} requests)")
        top_5_total = country_df.head(5)['requests'].sum()
        overall_total = country_df['requests'].sum()
        concentration = (top_5_total / overall_total) * 100
        analysis.append(f"Top 5 countries represent {concentration:.1f}% of all traffic")
    return analysis

def create_advanced_logs_analysis(adv_df):
    """Create advanced behavioral analysis"""
    analysis = []
    if not adv_df.empty:
        high_rate = adv_df[adv_df['req_per_min'] > 100]
        high_error = adv_df[adv_df['error_rate'] > 0.5]
        analysis.append(f"High-rate IPs (>100 req/min): {len(high_rate)}")
        analysis.append(f"High error rate IPs (>50%): {len(high_error)}")
        avg_req_rate = adv_df['req_per_min'].mean()
        avg_error_rate = adv_df['error_rate'].mean()
        analysis.append(f"Average request rate: {avg_req_rate:.1f} req/min")
        analysis.append(f"Average error rate: {avg_error_rate:.1%}")
    return analysis

def create_ddos_analysis(ddos_df):
    """Create DDoS incident analysis"""
    analysis = []
    if not ddos_df.empty:
        total_incidents = len(ddos_df)
        max_rps = ddos_df['peak_rps'].max()
        max_ips = ddos_df['unique_ips'].max()
        analysis.append(f"Total DDoS incidents: {total_incidents}")
        analysis.append(f"Peak RPS observed: {max_rps:,}")
        analysis.append(f"Maximum unique IPs in single incident: {max_ips:,}")
        recent_incidents = ddos_df[ddos_df['window_start'] >= (datetime.now() - timedelta(days=7)).isoformat()]
        analysis.append(f"Recent incidents (last 7 days): {len(recent_incidents)}")
    return analysis

def create_enhanced_html_report(report_start, report_end, tables, report_figs, analyses):
    """Create comprehensive HTML report with all visualizations and analyses"""
    parts = [
        "<html><head><meta charset='utf-8'><title>Blue‑Guard SIEM - Comprehensive Security Report</title>"
        "<style>"
        "body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0e1117;color:#f0f2f6;line-height:1.6;margin:0;padding:20px;}"
        "h1{color:#4ba3c7;text-align:center;margin-bottom:30px;font-size:2.5em;}"
        "h2{color:#4ba3c7;margin-top:40px;margin-bottom:20px;border-bottom:2px solid #4ba3c7;padding-bottom:10px;}"
        "h3{color:#7dd3fc;margin-top:30px;margin-bottom:15px;}"
        ".analysis{background:#1a1d24;padding:20px;border-radius:10px;margin:20px 0;border-left:4px solid #4ba3c7;}"
        ".analysis h4{color:#4ba3c7;margin-top:0;}"
        ".analysis ul{margin:10px 0;padding-left:20px;}"
        ".analysis li{margin:5px 0;color:#b7e0fa;}"
        ".summary{background:#1a1d24;padding:25px;border-radius:10px;margin:30px 0;border:2px solid #4ba3c7;}"
        ".metric{display:inline-block;margin:10px 20px;padding:15px;background:#2a2e36;border-radius:8px;min-width:150px;text-align:center;}"
        ".metric-value{font-size:2em;font-weight:bold;color:#4ba3c7;}"
        ".metric-label{color:#b7b7b7;font-size:0.9em;}"
        "table{background:#181c25;color:#f0f2f6;border-radius:8px;margin:20px 0;width:100%;border-collapse:collapse;}"
        "th,td{padding:12px;text-align:left;border-bottom:1px solid #2a2e36;}"
        "th{background:#2a2e36;color:#4ba3c7;font-weight:bold;}"
        "tr:hover{background:#1a1d24;}"
        ".chart-container{margin:20px 0;padding:20px;background:#1a1d24;border-radius:10px;}"
        ".risk-high{color:#ff6b6b;font-weight:bold;}"
        ".risk-medium{color:#ffd93d;font-weight:bold;}"
        ".risk-low{color:#6bcf7f;font-weight:bold;}"
        ".footer{text-align:center;margin-top:50px;padding:20px;color:#7dd3fc;border-top:1px solid #2a2e36;}"
        "</style></head><body>"
    ]
    parts.append(f"""
    <h1>🛡️ Blue‑Guard SIEM - Comprehensive Security Report</h1>
    <div class="summary">
        <h3>📊 Report Summary</h3>
        <p><strong>Analysis Period:</strong> {report_start.strftime('%Y-%m-%d %H:%M')} to {report_end.strftime('%Y-%m-%d %H:%M')}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """)
    parts.append('<h2>📋 Executive Summary</h2>')
    parts.append('<div class="summary">')
    total_logs = len(tables.get("Raw Logs Summary", pd.DataFrame()))
    suspicious_ips = len(tables.get("Suspicious IPs", pd.DataFrame()))
    blocked_ips = len(tables.get("Blocked IPs", pd.DataFrame()))
    ddos_incidents = len(tables.get("DDoS Incidents", pd.DataFrame()))
    parts.append(f"""
    <div class="metric">
        <div class="metric-value">{total_logs:,}</div>
        <div class="metric-label">Total Log Events</div>
    </div>
    <div class="metric">
        <div class="metric-value">{suspicious_ips:,}</div>
        <div class="metric-label">Suspicious IPs</div>
    </div>
    <div class="metric">
        <div class="metric-value">{blocked_ips:,}</div>
        <div class="metric-label">Blocked IPs</div>
    </div>
    <div class="metric">
        <div class="metric-value">{ddos_incidents:,}</div>
        <div class="metric-label">DDoS Incidents</div>
    </div>
    """)
    parts.append('</div>')
    threat_level = "LOW"
    threat_color = "risk-low"
    if ddos_incidents > 5 or suspicious_ips > 100:
        threat_level = "HIGH"
        threat_color = "risk-high"
    elif ddos_incidents > 1 or suspicious_ips > 20:
        threat_level = "MEDIUM"
        threat_color = "risk-medium"
    parts.append(f"""
    <div class="analysis">
        <h4>🚨 Overall Threat Level: <span class="{threat_color}">{threat_level}</span></h4>
        <p>Based on DDoS incidents, suspicious IP activity, and blocking patterns observed during the analysis period.</p>
    </div>
    """)
    sections = [
        ("🕐 Traffic Patterns & Activity Analysis", "traffic_analysis"),
        ("🚨 Threat Landscape & Security Events", "threat_analysis"),
        ("🌍 Geographical Distribution", "geo_analysis"),
        ("🧠 Advanced Behavioral Analysis", "behavioral_analysis"),
        ("⚡ DDoS & Attack Incidents", "ddos_analysis"),
        ("🔄 System Performance & Metrics", "performance_analysis")
    ]
    for section_title, section_key in sections:
        parts.append(f'<h2>{section_title}</h2>')
        if section_key in analyses:
            parts.append('<div class="analysis">')
            parts.append(f'<h4>Key Insights:</h4>')
            parts.append('<ul>')
            for insight in analyses[section_key]:
                parts.append(f'<li>{insight}</li>')
            parts.append('</ul>')
            parts.append('</div>')
        section_figs = {k: v for k, v in report_figs.items() if section_key in k.lower()}
        for fig_name, fig in section_figs.items():
            parts.append(f'<div class="chart-container">')
            parts.append(f'<h3>{fig_name}</h3>')
            if hasattr(fig, "to_html"):
                parts.append(fig.to_html(full_html=False, include_plotlyjs="cdn", config={"displayModeBar": False}))
            elif hasattr(fig, "savefig"):
                buf_png = io.BytesIO()
                fig.savefig(buf_png, format="png", facecolor="#0e1117", bbox_inches='tight')
                b64 = base64.b64encode(buf_png.getvalue()).decode()
                parts.append(f"<img src='data:image/png;base64,{b64}' style='max-width:100%; height:auto;'/>")
            parts.append('</div>')
    parts.append('<h2>📊 Detailed Data Tables</h2>')
    for table_name, df in tables.items():
        if not df.empty:
            parts.append(f'<h3>{table_name}</h3>')
            display_df = df.head(20) if len(df) > 20 else df
            parts.append(display_df.to_html(index=False, border=0, classes="dataframe", 
                                          justify="center", na_rep="N/A", table_id=table_name.replace(" ", "_")))
            if len(df) > 20:
                parts.append(f'<p><em>Showing top 20 of {len(df)} total records</em></p>')
        else:
            parts.append(f'<h3>{table_name}</h3>')
            parts.append('<p><em>No data available for this section</em></p>')
    parts.append(f"""
    <div class="footer">
        <p>Blue Guard SIEM © 2025 - Comprehensive Security Analysis Report</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Period: {report_start.strftime('%Y-%m-%d')} to {report_end.strftime('%Y-%m-%d')}</p>
    </div>
    """)
    parts.append("</body></html>")
    return "\n".join(parts).encode("utf-8")

# --- Reports Tab ---
# --- Helper functions for bounds ---
def _bounds(table: str, column: str):
    q = f"SELECT MIN({column}) AS min_t, MAX({column}) AS max_t FROM {table}"
    df = _run_sql(q)
    if df.empty or df.isnull().any(axis=None):
        return None, None
    return pd.to_datetime(df.min_t[0]), pd.to_datetime(df.max_t[0])

LOG_MIN, LOG_MAX = _bounds("logs", "time")
SUS_MIN, SUS_MAX = _bounds("ip_suspicious", "time")
BLK_MIN, BLK_MAX = _bounds("blocked_log", "backend_blocked_at")
ADV_MIN, ADV_MAX = _bounds("advanced_logs", "first_time_of_access")
DDOS_MIN, DDOS_MAX = _bounds("ddos_multiple_ip", "window_start")

# Global span across all tables
GLOBAL_MIN = min(ts for ts in (LOG_MIN, SUS_MIN, BLK_MIN, ADV_MIN, DDOS_MIN) if ts is not None)
GLOBAL_MAX = max(ts for ts in (LOG_MAX, SUS_MAX, BLK_MAX, ADV_MAX, DDOS_MAX) if ts is not None)

def get_latest_platform_pie(static_dir):
    pngs = sorted(static_dir.glob("platform_pie_day_*.png"), reverse=True)
    return pngs[0] if pngs else None

def create_hourly_activity_analysis(df_hourly):
    df_hourly['hour'] = df_hourly['hour'].astype(int)

    """Create comprehensive hourly activity analysis"""
    analysis = []
    peak_hours = df_hourly.nlargest(3, 'requests')['hour'].tolist()
    low_hours = df_hourly.nsmallest(3, 'requests')['hour'].tolist()
    analysis.append(f"Peak activity hours: {', '.join(map(str, peak_hours))}")
    analysis.append(f"Low activity hours: {', '.join(map(str, low_hours))}")
    business_hours = df_hourly[(df_hourly['hour'] >= 9) & (df_hourly['hour'] <= 17)]
    after_hours = df_hourly[(df_hourly['hour'] < 9) | (df_hourly['hour'] > 17)]
    business_total = business_hours['requests'].sum()
    after_hours_total = after_hours['requests'].sum()
    analysis.append(f"Business hours (9-17): {business_total:,} requests ({business_total/(business_total+after_hours_total)*100:.1f}%)")
    analysis.append(f"After hours: {after_hours_total:,} requests ({after_hours_total/(business_total+after_hours_total)*100:.1f}%)")
    return analysis

def create_threat_analysis(sus_df, blocked_df):
    """Create threat landscape analysis"""
    analysis = []
    total_suspicious = len(sus_df)
    total_blocked = len(blocked_df)
    analysis.append(f"Total suspicious events: {total_suspicious:,}")
    analysis.append(f"Total blocked IPs: {total_blocked:,}")
    if not sus_df.empty:
        top_reasons = sus_df['reason'].value_counts().head(3)
        analysis.append(f"Top threat types: {', '.join(top_reasons.index.tolist())}")
    if total_suspicious > 0:
        block_rate = (total_blocked / total_suspicious) * 100
        analysis.append(f"Block rate: {block_rate:.1f}% of suspicious IPs were blocked")
    return analysis

def create_geographical_analysis(country_df):
    """Create geographical threat analysis"""
    analysis = []
    if not country_df.empty:
        total_countries = len(country_df)
        top_country = country_df.iloc[0]
        analysis.append(f"Traffic from {total_countries} countries")
        analysis.append(f"Top country: {top_country['country']} ({top_country['requests']:,} requests)")
        top_5_total = country_df.head(5)['requests'].sum()
        overall_total = country_df['requests'].sum()
        concentration = (top_5_total / overall_total) * 100
        analysis.append(f"Top 5 countries represent {concentration:.1f}% of all traffic")
    return analysis

def create_advanced_logs_analysis(adv_df):
    """Create advanced behavioral analysis"""
    analysis = []
    if not adv_df.empty:
        high_rate = adv_df[adv_df['req_per_min'] > 100]
        high_error = adv_df[adv_df['error_rate'] > 0.5]
        analysis.append(f"High-rate IPs (>100 req/min): {len(high_rate)}")
        analysis.append(f"High error rate IPs (>50%): {len(high_error)}")
        avg_req_rate = adv_df['req_per_min'].mean()
        avg_error_rate = adv_df['error_rate'].mean()
        analysis.append(f"Average request rate: {avg_req_rate:.1f} req/min")
        analysis.append(f"Average error rate: {avg_error_rate:.1%}")
    return analysis

def create_ddos_analysis(ddos_df):
    """Create DDoS incident analysis"""
    analysis = []
    if not ddos_df.empty:
        total_incidents = len(ddos_df)
        max_rps = ddos_df['peak_rps'].max()
        max_ips = ddos_df['unique_ips'].max()
        analysis.append(f"Total DDoS incidents: {total_incidents}")
        analysis.append(f"Peak RPS observed: {max_rps:,}")
        analysis.append(f"Maximum unique IPs in single incident: {max_ips:,}")
        recent_incidents = ddos_df[ddos_df['window_start'] >= (datetime.now() - timedelta(days=7)).isoformat()]
        analysis.append(f"Recent incidents (last 7 days): {len(recent_incidents)}")
    return analysis

def create_enhanced_html_report(report_start, report_end, tables, report_figs, analyses):
    """Create comprehensive HTML report with all visualizations and analyses"""
    parts = [
        "<html><head><meta charset='utf-8'><title>Blue‑Guard SIEM - Comprehensive Security Report</title>"
        "<style>"
        "body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0e1117;color:#f0f2f6;line-height:1.6;margin:0;padding:20px;}"
        "h1{color:#4ba3c7;text-align:center;margin-bottom:30px;font-size:2.5em;}"
        "h2{color:#4ba3c7;margin-top:40px;margin-bottom:20px;border-bottom:2px solid #4ba3c7;padding-bottom:10px;}"
        "h3{color:#7dd3fc;margin-top:30px;margin-bottom:15px;}"
        ".analysis{background:#1a1d24;padding:20px;border-radius:10px;margin:20px 0;border-left:4px solid #4ba3c7;}"
        ".analysis h4{color:#4ba3c7;margin-top:0;}"
        ".analysis ul{margin:10px 0;padding-left:20px;}"
        ".analysis li{margin:5px 0;color:#b7e0fa;}"
        ".summary{background:#1a1d24;padding:25px;border-radius:10px;margin:30px 0;border:2px solid #4ba3c7;}"
        ".metric{display:inline-block;margin:10px 20px;padding:15px;background:#2a2e36;border-radius:8px;min-width:150px;text-align:center;}"
        ".metric-value{font-size:2em;font-weight:bold;color:#4ba3c7;}"
        ".metric-label{color:#b7b7b7;font-size:0.9em;}"
        "table{background:#181c25;color:#f0f2f6;border-radius:8px;margin:20px 0;width:100%;border-collapse:collapse;}"
        "th,td{padding:12px;text-align:left;border-bottom:1px solid #2a2e36;}"
        "th{background:#2a2e36;color:#4ba3c7;font-weight:bold;}"
        "tr:hover{background:#1a1d24;}"
        ".chart-container{margin:20px 0;padding:20px;background:#1a1d24;border-radius:10px;}"
        ".risk-high{color:#ff6b6b;font-weight:bold;}"
        ".risk-medium{color:#ffd93d;font-weight:bold;}"
        ".risk-low{color:#6bcf7f;font-weight:bold;}"
        ".footer{text-align:center;margin-top:50px;padding:20px;color:#7dd3fc;border-top:1px solid #2a2e36;}"
        "</style></head><body>"
    ]
    parts.append(f"""
    <h1>🛡️ Blue‑Guard SIEM - Comprehensive Security Report</h1>
    <div class="summary">
        <h3>📊 Report Summary</h3>
        <p><strong>Analysis Period:</strong> {report_start.strftime('%Y-%m-%d %H:%M')} to {report_end.strftime('%Y-%m-%d %H:%M')}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """)
    parts.append('<h2>📋 Executive Summary</h2>')
    parts.append('<div class="summary">')
    total_logs = len(tables.get("Raw Logs Summary", pd.DataFrame()))
    suspicious_ips = len(tables.get("Suspicious IPs", pd.DataFrame()))
    blocked_ips = len(tables.get("Blocked IPs", pd.DataFrame()))
    ddos_incidents = len(tables.get("DDoS Incidents", pd.DataFrame()))
    parts.append(f"""
    <div class="metric">
        <div class="metric-value">{total_logs:,}</div>
        <div class="metric-label">Total Log Events</div>
    </div>
    <div class="metric">
        <div class="metric-value">{suspicious_ips:,}</div>
        <div class="metric-label">Suspicious IPs</div>
    </div>
    <div class="metric">
        <div class="metric-value">{blocked_ips:,}</div>
        <div class="metric-label">Blocked IPs</div>
    </div>
    <div class="metric">
        <div class="metric-value">{ddos_incidents:,}</div>
        <div class="metric-label">DDoS Incidents</div>
    </div>
    """)
    parts.append('</div>')
    threat_level = "LOW"
    threat_color = "risk-low"
    if ddos_incidents > 5 or suspicious_ips > 100:
        threat_level = "HIGH"
        threat_color = "risk-high"
    elif ddos_incidents > 1 or suspicious_ips > 20:
        threat_level = "MEDIUM"
        threat_color = "risk-medium"
    parts.append(f"""
    <div class="analysis">
        <h4>🚨 Overall Threat Level: <span class="{threat_color}">{threat_level}</span></h4>
        <p>Based on DDoS incidents, suspicious IP activity, and blocking patterns observed during the analysis period.</p>
    </div>
    """)
    sections = [
        ("🕐 Traffic Patterns & Activity Analysis", "traffic_analysis"),
        ("🚨 Threat Landscape & Security Events", "threat_analysis"),
        ("🌍 Geographical Distribution", "geo_analysis"),
        ("🧠 Advanced Behavioral Analysis", "behavioral_analysis"),
        ("⚡ DDoS & Attack Incidents", "ddos_analysis"),
        ("🔄 System Performance & Metrics", "performance_analysis"),
        ("🧬 IP Category Distributions", "category_analysis") 
    ]
    for section_title, section_key in sections:
        parts.append(f'<h2>{section_title}</h2>')
        if section_key in analyses:
            parts.append('<div class="analysis">')
            parts.append(f'<h4>Key Insights:</h4>')
            parts.append('<ul>')
            for insight in analyses[section_key]:
                parts.append(f'<li>{insight}</li>')
            parts.append('</ul>')
            parts.append('</div>')
        section_figs = {k: v for k, v in report_figs.items() if section_key in k.lower()}
        for fig_name, fig in section_figs.items():
            parts.append(f'<div class="chart-container">')
            parts.append(f'<h3>{fig_name}</h3>')
            if hasattr(fig, "to_html"):
                parts.append(fig.to_html(full_html=False, include_plotlyjs="cdn", config={"displayModeBar": False}))
            elif hasattr(fig, "savefig"):
                buf_png = io.BytesIO()
                fig.savefig(buf_png, format="png", facecolor="#0e1117", bbox_inches='tight')
                b64 = base64.b64encode(buf_png.getvalue()).decode()
                parts.append(f"<img src='data:image/png;base64,{b64}' style='max-width:100%; height:auto;'/>")
            parts.append('</div>')
    parts.append('<h2>📊 Detailed Data Tables</h2>')
    for table_name, df in tables.items():
        if not df.empty:
            parts.append(f'<h3>{table_name}</h3>')
            display_df = df.head(20) if len(df) > 20 else df
            parts.append(display_df.to_html(index=False, border=0, classes="dataframe", 
                                          justify="center", na_rep="N/A", table_id=table_name.replace(" ", "_")))
            if len(df) > 20:
                parts.append(f'<p><em>Showing top 20 of {len(df)} total records</em></p>')
        else:
            parts.append(f'<h3>{table_name}</h3>')
            parts.append('<p><em>No data available for this section</em></p>')
    parts.append(f"""
    <div class="footer">
        <p>Blue Guard SIEM © 2025 - Comprehensive Security Analysis Report</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Period: {report_start.strftime('%Y-%m-%d')} to {report_end.strftime('%Y-%m-%d')}</p>
    </div>
    """)
    parts.append("</body></html>")
    return "\n".join(parts).encode("utf-8")

# --- Reports Tab ---
def render_reports_tab():
    st.title("📄 Comprehensive Security Analysis Report")
    st.caption(f"Full data span: {GLOBAL_MIN.date()} to {GLOBAL_MAX.date()}")


    # Set timezone
    IST = pytz.timezone("Asia/Kolkata")

    # 📅 Date input from UI (you can change default dates)
    # report_range = st.date_input("🕒 Select Report Time Range", [datetime(2025, 7, 10), datetime(2025, 7, 13)])
    report_range = st.date_input(
    "🕒 Select Report Time Range",
    value=(GLOBAL_MIN.date(), GLOBAL_MAX.date()),  # ✅ full span of your data
    min_value=GLOBAL_MIN.date(),
    max_value=GLOBAL_MAX.date()
    )


    # Normalize time range (start of day to end of day in IST)
    report_start_dt = IST.localize(datetime.combine(report_range[0], time.min))
    report_end_dt = IST.localize(datetime.combine(report_range[1], time.max))

    # report_start = report_start_dt.isoformat()
    # report_end = report_end_dt.isoformat()
    # Define both datetime and string versions
    report_start_dt = IST.localize(datetime.combine(report_range[0], time.min))
    report_end_dt = IST.localize(datetime.combine(report_range[1], time.max))

    # report_start_str = report_start_dt.strftime("%Y-%m-%d %H:%M:%S")
    # report_end_str   = report_end_dt.strftime("%Y-%m-%d %H:%M:%S")

    report_start_str = report_start_dt.isoformat()
    report_end_str   = report_end_dt.isoformat()




    # Debug print
    st.write("🕒 Report Time Range")
    st.code(f"Start: {report_start_str}\nEnd  : {report_end_str}")



    # # Date range selector
    # report_range = st.date_input(
    #     "Select analysis period for comprehensive report",
    #     value=(GLOBAL_MIN.date(), GLOBAL_MAX.date()),
    #     min_value=GLOBAL_MIN.date(),
    #     max_value=GLOBAL_MAX.date(),
    #     key="comprehensive_report_range",
    # )
    
    # IST = pytz.timezone('Asia/Kolkata')
    # report_start = IST.localize(datetime.combine(report_range[0], datetime.min.time()))
    # report_end = IST.localize(datetime.combine(report_range[1], datetime.max.time()))


    # report_start = datetime.combine(report_range[0], datetime.min.time())
    # report_end = datetime.combine(report_range[1], datetime.max.time())

    # Report generation
    if st.button("🔄 Generate Comprehensive Security Report", use_container_width=True):
        with st.spinner("🔍 Analyzing security data and generating comprehensive report..."):
            tables = {}

            # Raw logs summary
            tables["Raw Logs Summary"] = _run_sql("""
                SELECT country, method, status, COUNT(*) as requests,
                       AVG(size) as avg_size, MIN(time) as first_seen, MAX(time) as last_seen
                FROM logs 
                WHERE time BETWEEN ? AND ?
                GROUP BY country, method, status
                ORDER BY requests DESC
            """,params=[report_start_str, report_end_str])

            # Suspicious IPs
            tables["Suspicious IPs"] = _run_sql("""
                SELECT suspiciousIp, time, reason, detection_count
                FROM ip_suspicious
                WHERE time BETWEEN ? AND ?
                ORDER BY detection_count DESC, time DESC
            """,params=[report_start_str, report_end_str])

            # Blocked IPs
            tables["Blocked IPs"] = _run_sql("""
                SELECT ip, detected_at, backend_blocked_at, detection_count,
                       client_blocked_at, client_block_status
                FROM blocked_log
                WHERE backend_blocked_at BETWEEN ? AND ?
                ORDER BY detection_count DESC
            """,params=[report_start_str, report_end_str])

            # Advanced logs
            tables["Advanced Behavioral Analysis"] = _run_sql("""
                SELECT ip, req_per_min, unique_urls, error_rate, avg_req_size_bytes,
                       method_ratio_post_by_get, first_time_of_access
                FROM advanced_logs
                WHERE first_time_of_access BETWEEN ? AND ?
                ORDER BY req_per_min DESC
            """,params=[report_start_str, report_end_str])

            # DDoS incidents
            tables["DDoS Incidents"] = _run_sql("""
            SELECT window_start, window_end, duration_s, total_hits,
                   unique_ips, peak_rps, inserted_at
            FROM ddos_multiple_ip
            WHERE substr(window_start, 1, 10) BETWEEN ? AND ?
            ORDER BY peak_rps DESC
        """, params=[
                report_start_dt.date().isoformat(),
                report_end_dt.date().isoformat()
            ])


            # Hourly analysis
            tables["Hourly Activity Pattern"] = _run_sql("""
                SELECT strftime('%H', time) as hour, COUNT(*) as requests,
                       COUNT(DISTINCT ip) as unique_ips,
                       AVG(size) as avg_size
                FROM logs
                WHERE time BETWEEN ? AND ?
                GROUP BY hour
                ORDER BY hour
            """,params=[report_start_str, report_end_str])

            # Country analysis
            tables["Geographical Distribution"] = _run_sql("""
                SELECT country, COUNT(*) as requests,
                       COUNT(DISTINCT ip) as unique_ips,
                       AVG(size) as avg_request_size
                FROM logs
                WHERE time BETWEEN ? AND ?
                GROUP BY country
                ORDER BY requests DESC
            """,params=[report_start_str, report_end_str])

            # IP categorization from ip_eachHour_category
            tables["IP Behavioral Categories"] = _run_sql("""
                SELECT category, COUNT(DISTINCT ip) as unique_ips,
                       AVG(hour) as avg_active_hour
                FROM ip_eachHour_category
                GROUP BY category
                ORDER BY unique_ips DESC
            """)

            # Generate visualizations
            report_figs = {}
            analyses = {}

            # Example color palettes
            BAR_COLORS = px.colors.qualitative.Bold
            PIE_COLORS = px.colors.qualitative.Pastel
            CHORO_COLORS = px.colors.sequential.Plasma
            SCATTER_COLORS = px.colors.sequential.Viridis


            # 1. Traffic Analysis (Bar)
            hourly_df = tables["Hourly Activity Pattern"]
            if not hourly_df.empty:
                fig_hourly = px.bar(
                    hourly_df, x='hour', y='requests',
                    title='Hourly Request Distribution',
                    labels={'hour': 'Hour of Day', 'requests': 'Number of Requests'},
                    color='requests',
                    color_continuous_scale='Plasma'
                )
                fig_hourly.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    xaxis=dict(showgrid=False, color='#f0f2f6'),
                    yaxis=dict(showgrid=True, gridcolor='#2a2e36', color='#f0f2f6')
                )
                report_figs["traffic_analysis_hourly"] = fig_hourly

            # 2. Threat Analysis (Pie and Line)
            sus_df = tables["Suspicious IPs"]
            blocked_df = tables["Blocked IPs"]
            if not sus_df.empty:
                sus_timeline = sus_df.copy()
                sus_timeline['date'] = pd.to_datetime(sus_timeline['time']).dt.date
                daily_threats = sus_timeline.groupby('date').size().reset_index(name='threats')
                # Line chart for timeline
                fig_threats = px.line(
                    daily_threats, x='date', y='threats',
                    title='Daily Threat Detection Timeline',
                    labels={'date': 'Date', 'threats': 'Suspicious Events'},
                    markers=True
                )
                fig_threats.update_traces(line_color='#FFD93D')
                fig_threats.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    xaxis=dict(showgrid=False, color='#f0f2f6'),
                    yaxis=dict(showgrid=True, gridcolor='#2a2e36', color='#f0f2f6')
                    )
                report_figs["threat_analysis_timeline"] = fig_threats

                # Pie chart for threat reasons
                report_figs["threat_analysis_timeline"] = fig_threats
                threat_reasons = sus_df['reason'].value_counts().reset_index()
                threat_reasons.columns = ['reason', 'count']
                fig_reasons = px.pie(
                    threat_reasons, values='count', names='reason',
                    title='Distribution of Threat Types',
                    color_discrete_sequence=PIE_COLORS
                )
                fig_reasons.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    legend_font_color='#f0f2f6'
                )
                report_figs["threat_analysis_reasons"] = fig_reasons

            # 3. Geographical Analysis (Choropleth and Bar)
            geo_df = tables["Geographical Distribution"]
            if not geo_df.empty:
                top_countries = geo_df.head(10)
                fig_geo = px.choropleth(
                    geo_df, locations='country', locationmode='country names',
                    color='requests', hover_data=['unique_ips'],
                    title='Global Request Distribution',
                    color_continuous_scale=CHORO_COLORS
                )
                fig_geo.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7'
                )
                report_figs["geo_analysis_map"] = fig_geo

                fig_countries = px.bar(
                    top_countries, x='country', y='requests',
                    title='Top 10 Countries by Request Volume',
                    color='requests',
                    color_continuous_scale='Turbo'
                )
                fig_countries.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    xaxis=dict(showgrid=False, color='#f0f2f6'),
                    yaxis=dict(showgrid=True, gridcolor='#2a2e36', color='#f0f2f6')
                )
                report_figs["geo_analysis_top_countries"] = fig_countries

            # 4. Advanced Behavioral Analysis (Scatter and Histogram)
            adv_df = tables["Advanced Behavioral Analysis"]
            if not adv_df.empty:
                fig_scatter = px.scatter(
                    adv_df, x='req_per_min', y='error_rate',
                    size='unique_urls', hover_data=['ip'],
                    title='IP Behavior: Request Rate vs Error Rate',
                    color='error_rate',
                    color_continuous_scale='Turbo'
                )
                fig_scatter.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    xaxis=dict(color='#f0f2f6'),
                    yaxis=dict(color='#f0f2f6')
                )
                report_figs["behavioral_analysis_scatter"] = fig_scatter

                fig_methods = px.histogram(
                    adv_df, x='method_ratio_post_by_get', nbins=20,
                    title='Distribution of POST/GET Ratios',
                    color_discrete_sequence=BAR_COLORS
                )
                fig_methods.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    xaxis=dict(color='#f0f2f6'),
                    yaxis=dict(color='#f0f2f6')
                )
                report_figs["behavioral_analysis_methods"] = fig_methods

            # 5. DDoS Analysis (Scatter)
            ddos_df = tables["DDoS Incidents"]
            if not ddos_df.empty:
                ddos_timeline = ddos_df.copy()
                fig_ddos = px.scatter(
                    ddos_timeline, x='window_start', y='peak_rps',
                    size='unique_ips', hover_data=['total_hits'],
                    title='DDoS Incidents: Peak RPS vs Time',
                    color='peak_rps',
                    color_continuous_scale='Turbo'
                )
                fig_ddos.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    xaxis=dict(color='#f0f2f6'),
                    yaxis=dict(color='#f0f2f6')
                )
                report_figs["ddos_analysis_timeline"] = fig_ddos

            # 6. Platform Distribution (NEW)
            platform_df = _run_sql("""
                SELECT agent, COUNT(*) as count
                FROM logs
                WHERE time BETWEEN ? AND ?
                GROUP BY agent
                ORDER BY count DESC
                LIMIT 100
            """,params=[report_start_str, report_end_str])

            if not platform_df.empty:
                # Classify common platforms
                def get_platform(agent):
                    a = agent.lower()
                    if "windows" in a: return "Windows"
                    elif "linux" in a: return "Linux"
                    elif "mac" in a: return "macOS"
                    elif "android" in a: return "Android"
                    elif "ios" in a or "iphone" in a: return "iOS"
                    else: return "Other"
    
                platform_df["platform"] = platform_df["agent"].apply(get_platform)
                platform_summary = platform_df.groupby("platform")["count"].sum().reset_index()

                fig_platform = px.pie(
                    platform_summary, names="platform", values="count",
                    title="Platform Distribution of Request Sources",
                    color_discrete_sequence=PIE_COLORS
                )
                fig_platform.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    legend_font_color='#f0f2f6'
                )
                report_figs["traffic_analysis_platform_distribution"] = fig_platform


            # 7. Method & Status Code Breakdown
            log_summary = tables["Raw Logs Summary"]
            if not log_summary.empty:
                method_summary = log_summary.groupby("method")["requests"].sum().reset_index()
                fig_methods = px.bar(method_summary, x="method", y="requests", title="HTTP Methods Breakdown",
                         color="requests", color_continuous_scale="Viridis")
                fig_methods.update_layout(template='plotly_dark', plot_bgcolor='#0e1117', paper_bgcolor='#0e1117',
                              font_color='#f0f2f6', title_font_color='#4ba3c7')
                report_figs["traffic_analysis_method_distribution"] = fig_methods

                status_summary = log_summary.groupby("status")["requests"].sum().reset_index()
                fig_status = px.bar(status_summary, x="status", y="requests", title="HTTP Status Code Distribution",
                        color="requests", color_continuous_scale="Plasma")
                fig_status.update_layout(template='plotly_dark', plot_bgcolor='#0e1117', paper_bgcolor='#0e1117',
                             font_color='#f0f2f6', title_font_color='#4ba3c7')
                report_figs["traffic_analysis_status_distribution"] = fig_status


            #8. top urls accessed
            top_urls = _run_sql("""
            SELECT url, COUNT(*) as requests
            FROM logs
            WHERE time BETWEEN ? AND ?
            GROUP BY url
            ORDER BY requests DESC
            LIMIT 15
            """,params=[report_start_str, report_end_str])

            if not top_urls.empty:
                fig_top_urls = px.bar(top_urls, x='url', y='requests', title='Top 15 Requested URLs',
                          color='requests', color_continuous_scale='Turbo')
                fig_top_urls.update_layout(template='plotly_dark', plot_bgcolor='#0e1117',
                                           paper_bgcolor='#0e1117', font_color='#f0f2f6',
                                           title_font_color='#4ba3c7', xaxis_tickangle=-45)
                report_figs["traffic_analysis_top_urls"] = fig_top_urls


            #9. request size distribution(histogram)
            size_df = _run_sql("""
            SELECT size FROM logs
            WHERE time BETWEEN ? AND ?
            """,params=[report_start_str, report_end_str])

            if not size_df.empty:
                fig_sizes = px.histogram(size_df, x='size', nbins=30, title='Request Size Distribution (Bytes)',
                                         color_discrete_sequence=BAR_COLORS)
                fig_sizes.update_layout(template='plotly_dark', plot_bgcolor='#0e1117',
                                        paper_bgcolor='#0e1117', font_color='#f0f2f6',
                                        title_font_color='#4ba3c7')
                report_figs["traffic_analysis_size_distribution"] = fig_sizes


            #10. user agent 
            agent_df = _run_sql("""
            SELECT agent, COUNT(*) as count
            FROM logs
            WHERE time BETWEEN ? AND ?
            GROUP BY agent
            ORDER BY count DESC
            LIMIT 10
            """,params=[report_start_str, report_end_str])

            if not agent_df.empty:
                fig_agents = px.bar(
                    agent_df.sort_values("count"),  # ascending so largest appears at top
                    x='count',
                    y='agent',
                    orientation='h',
                    title='Top 10 User Agents',
                    color='count',
                    color_continuous_scale='Sunset'
                )
                fig_agents.update_layout(
                    template='plotly_dark',
                    plot_bgcolor='#0e1117',
                    paper_bgcolor='#0e1117',
                    font_color='#f0f2f6',
                    title_font_color='#4ba3c7',
                    yaxis=dict(title='User Agent', tickfont=dict(size=10), automargin=True),
                    xaxis=dict(title='Request Count'),
                    margin=dict(l=160, r=20, t=60, b=40),
                    height=500
                )
                report_figs["traffic_analysis_user_agents"] = fig_agents


            #11. hourly ip category split
            ipcat_df = _run_sql("""
            SELECT hour, category, COUNT(*) as count
            FROM ip_eachHour_category
            WHERE hour IS NOT NULL
            GROUP BY hour, category
            """)

            if not ipcat_df.empty:
                # Ensure hour ranges are treated as strings
                ipcat_df["hour"] = ipcat_df["hour"].astype(str)

                # Explicit ordering of hour ranges
                hour_order = [f"{i}-{i+1}" for i in range(24)]
                ipcat_df["hour"] = pd.Categorical(ipcat_df["hour"], categories=hour_order, ordered=True)

                CUSTOM_COLORS = ['#4ba3c7', '#FFD93D', '#EF476F', '#06D6A0', '#FFA07A', '#8E7CC3']

                fig_category_hour = px.bar(
                    ipcat_df,
                    x="hour",
                    y="count",
                    color="category",
                    barmode="stack",
                    title="Hourly Breakdown of Suspicious Categories",
                    color_discrete_sequence=CUSTOM_COLORS
                )

                # 🛠 Force x-axis to use category mode
                fig_category_hour.update_layout(
                    xaxis_type="category",
                    template="plotly_dark",
                    plot_bgcolor="#0e1117",
                    paper_bgcolor="#0e1117",
                    font_color="#f0f2f6",
                    title_font_color="#4ba3c7",
                    xaxis_title="Hour Range",
                    yaxis_title="Count"
                )

                report_figs["category_analysis_hourly_category_stack"] = fig_category_hour




            #12. category sistribution
            cat_df = _run_sql("""
            SELECT category, COUNT(*) as count
            FROM ip_eachHour_category
            GROUP BY category
            ORDER BY count DESC
            """)

            if not cat_df.empty:
                fig_category_pie = px.pie(
                    cat_df, names="category", values="count",
                    title="Distribution of Suspicious Activity Categories",
                    color_discrete_sequence=PIE_COLORS
                )
                fig_category_pie.update_layout(
                    template="plotly_dark",
                    plot_bgcolor="#0e1117",
                    paper_bgcolor="#0e1117",
                    font_color="#f0f2f6",
                    title_font_color="#4ba3c7",
                    legend_font_color="#f0f2f6"
                )
                report_figs["category_analysis_suspicious_category_pie"] = fig_category_pie



            # 13. Performance metrics
            total_requests = sum(df['requests'].sum() if 'requests' in df.columns 
                               else len(df) for df in tables.values())
            analyses["performance_analysis"] = [
                f"Total processed events: {total_requests:,}",
                f"Analysis period: {(report_end_dt - report_start_dt).days} days",
                f"Average daily events: {total_requests / max(1, (report_end_dt - report_start_dt).days):,.0f}",
                f"Peak hourly rate: {hourly_df['requests'].max() if not hourly_df.empty else 0:,} requests/hour"
            ]
            analyses["category_analysis"] = [
                "Most frequent suspicious activity categories were identified using behavioral tagging.",
                "Hourly pattern shows spikes in certain categories at specific times of the day."
            ]


            # Generate HTML report
            html_report = create_enhanced_html_report(
                report_start_dt, report_end_dt, tables, report_figs, analyses
            )


            # Save report
            filename = f"BlueGuard_Comprehensive_Report_{report_start_dt.strftime('%Y%m%d')}_{report_end_dt.strftime('%Y%m%d')}.html"
            filepath = REPORTS_DIR / filename

            with open(filepath, 'wb') as f:
                f.write(html_report)

            st.success(f"✅ Comprehensive report generated successfully!")

            
            # --- INLINE PREVIEW OF THE JUST‑CREATED REPORT -------------
            with st.expander("👁️ Preview the new report", expanded=False):
                st.components.v1.html(
                    html_report.decode("utf-8"),
                    height=600,
                    scrolling=True
                )
            # Display key insights 
            st.subheader("🔍 Key Security Insights")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Events", f"{total_requests:,}")
            with col2:
                st.metric("Suspicious IPs", f"{len(tables['Suspicious IPs']):,}")
            with col3:
                st.metric("Blocked IPs", f"{len(tables['Blocked IPs']):,}")
            with col4:
                st.metric("DDoS Incidents", f"{len(tables['DDoS Incidents']):,}")

            # Provide download link for the new report
            with open(filepath, "rb") as f:
                bytes_data = f.read()
                b64 = base64.b64encode(bytes_data).decode()
                href = f'<a href="data:file/html;base64,{b64}" download="{filename}">⬇️ Download This Report</a>'
                st.markdown(href, unsafe_allow_html=True)


    # --- Section: View & Download Previous Reports ---
    st.header("📂 View & Download Previously Generated Reports")
    reports = sorted(REPORTS_DIR.glob("*.html"), reverse=True)

    if not reports:
        st.info("No previously generated reports found.")
    else:
        report_names = [r.name for r in reports]
        selected_report = st.selectbox("Select a report to view or download", report_names)

        if selected_report:
            report_path = REPORTS_DIR / selected_report

            # read HTML once
            with open(report_path, "r", encoding="utf-8") as f:
                report_html = f.read()

            # ── SAME INLINE PREVIEW STYLE AS GENERATION ────────────────
            with st.expander("👁️ Preview report", expanded=False):
                st.components.v1.html(
                    report_html,
                    height=600,
                    scrolling=True
                )

            # ── DOWNLOAD LINK (single button) ──────────────────────────
            with open(report_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()

            st.markdown(
                f'<a href="data:file/html;base64,{b64}" '
                f'download="{selected_report}">⬇️ Download Report</a>',
                unsafe_allow_html=True
            )


# To use in your Streamlit app, call render_reports_tab() in your main page logic.

with tabs[7]:              # 0‑based index → 7th element is "Report"
    render_reports_tab()   # 👈 this runs ONLY when the user clicks “Report”


# --- System ---
with tabs[8]:
    import platform
    import sys
    import socket
    import getpass
    import datetime

    st.title("⚙️ System Info & Settings")

    st.markdown(
        """
        <style>
            .sys-section {margin-top: 26px;}
            .sys-metric {font-size: 1.08em; color: #4ba3c7; font-weight: 600;}
            .sys-table th, .sys-table td {padding: 6px 10px;}
            .sys-table th {background: #232b3e; color: #ffe082;}
            .sys-table tr:nth-child(even) {background: #191b1f;}
            .sys-table tr:nth-child(odd) {background: #23262d;}
        </style>
        """, unsafe_allow_html=True
    )

    # --- Basic DB and Log Info ---
    st.markdown("#### Database & Log Summary")
    st.write(f"**DB file:** `{DB_PATH}`  • {os.path.getsize(DB_PATH)/(1024**2):.2f} MB")
    st.write(f"**Log‑time span:** {LOG_MIN} → {LOG_MAX}")
    st.write(f"**Ingest‑time span:** {ING_MIN} → {ING_MAX}")


    # --- DB Table Row Counts & Health ---
    st.markdown("<div class='sys-section'><b>Database Table Stats</b></div>", unsafe_allow_html=True)
    table_names = _run_sql("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")['name'].tolist()
    table_stats = []
    for t in table_names:
        try:
            count = _run_sql(f"SELECT COUNT(*) as cnt FROM {t}").iloc[0,0]
            table_stats.append({"Table": t, "Rows": count})
        except Exception:
            table_stats.append({"Table": t, "Rows": "?"})
    df_tables = pd.DataFrame(table_stats)
    st.dataframe(df_tables, hide_index=True, use_container_width=True)




    # --- Database Integrity Check ---
    st.markdown("<div class='sys-section'><b>Database Integrity Check</b></div>", unsafe_allow_html=True)
    try:
        integrity = _run_sql("PRAGMA integrity_check").iloc[0,0]
        if integrity == "ok":
            st.success("Database integrity: OK")
        else:
            st.warning(f"Database integrity issue: {integrity}")
    except Exception as e:
        st.error(f"Integrity check failed: {e}")

    # --- System Environment ---
    st.markdown("<div class='sys-section'><b>Host Environment</b></div>", unsafe_allow_html=True)
    try:
        import psutil
        uptime = str(datetime.timedelta(seconds=int((datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).total_seconds())))
    except ImportError:
        uptime = "N/A"
    except Exception:
        uptime = "N/A"
    env_info = {
        "Hostname": socket.gethostname(),
        "User": getpass.getuser(),
        "OS": f"{platform.system()} {platform.release()} ({platform.version()})",
        "Python": sys.version.split()[0],
        "Platform": platform.platform(),
        "Uptime": uptime,
        "Current Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    env_df = pd.DataFrame(list(env_info.items()), columns=["Property", "Value"])
    st.dataframe(env_df, hide_index=True, use_container_width=True)

    # --- Resource Usage ---
    st.markdown("<div class='sys-section'><b>Resource Usage</b></div>", unsafe_allow_html=True)
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(os.path.dirname(DB_PATH))
        col1, col2, col3 = st.columns(3)
        col1.metric("CPU Usage", f"{cpu:.1f} %")
        col2.metric("RAM Usage", f"{mem.percent:.1f} %", f"{mem.used//(1024**2)} MB / {mem.total//(1024**2)} MB")
        col3.metric("Disk Usage", f"{disk.percent:.1f} %", f"{disk.used//(1024**3)} GB / {disk.total//(1024**3)} GB")
    except ImportError:
        st.info("psutil not available for resource usage metrics.")
    except Exception:
        st.info("Resource usage metrics not available.")

    # --- Python Package Versions ---
    st.markdown("<div class='sys-section'><b>Python Package Versions</b></div>", unsafe_allow_html=True)
    try:
        pkgs = [
            ("streamlit", __import__("streamlit").__version__),
            ("pandas", __import__("pandas").__version__),
            ("plotly", __import__("plotly").__version__),
            ("seaborn", __import__("seaborn").__version__),
            ("numpy", __import__("numpy").__version__),
        ]
        pkg_df = pd.DataFrame(pkgs, columns=["Package", "Version"])
        st.dataframe(pkg_df, hide_index=True, use_container_width=True)
    except Exception:
        st.info("Could not determine all package versions.")

    # --- Download DB Button ---
    st.markdown("<div class='sys-section'><b>Database Export</b></div>", unsafe_allow_html=True)
    try:
        with open(DB_PATH, "rb") as f:
            st.download_button("Download Database File", f, file_name=os.path.basename(DB_PATH))
    except Exception:
        st.info("Database file not found or not accessible.")

    # --- Restart/Shutdown Info (display only, not action) ---
    st.markdown("<div class='sys-section'><b>System Actions</b></div>", unsafe_allow_html=True)
    st.info("To restart or shutdown the SIEM server, use your host system's controls or deployment scripts.")


# --- Footer ---
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#a1a9b7;font-size:12px;'>"
    "Blue Guard SIEM © 2025 – Unified Multi-Tab Dashboard</div>",
    unsafe_allow_html=True,
)








