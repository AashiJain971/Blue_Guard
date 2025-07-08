import streamlit as st
import pandas as pd
import hashlib
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import sqlite3, pathlib, os, io, base64, zipfile, re
from datetime import datetime, timedelta
import numpy as np

# --- Setup ---
BASE_DIR = pathlib.Path().absolute()
DB_PATH = str(BASE_DIR / "access_logs.db")
ASSETS = BASE_DIR / "assets"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
DARK_BG = "#0e1117"
sns.set_theme(style="whitegrid", palette="viridis")
plt.style.use("ggplot")
plt.rcParams["figure.figsize"] = (12, 6)
plt.rcParams["font.size"] = 12
plt.rcParams["axes.facecolor"] = DARK_BG
plt.rcParams["figure.facecolor"] = DARK_BG

def _run_sql(query: str, **kw) -> pd.DataFrame:
    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query(query, conn, **kw)

def get_csv_download_link(df, filename):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    return f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download CSV</a>'


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

def get_bounds(col):
    df = _run_sql(f"SELECT MIN({col}) as min_t, MAX({col}) as max_t FROM logs")
    if df.empty or df.isnull().any(axis=None):
        now = datetime.now().astimezone()
        return now, now
    return pd.to_datetime(df.iloc[0]["min_t"]), pd.to_datetime(df.iloc[0]["max_t"])

LOG_MIN, LOG_MAX = get_bounds("time")
ING_MIN, ING_MAX = get_bounds("ingest_ts")

# --- Sidebar: Logo and time spans only ---
with st.sidebar:
    st.image(str(ASSETS / "BlueGuardLogo.jpg"), use_container_width=True)
    st.markdown("### Dataset Time Spans")
    st.write(f"**Log time:** {LOG_MIN.date()} → {LOG_MAX.date()}")
    st.write(f"**Ingest time:** {ING_MIN.date()} → {ING_MAX.date()}")
    st.markdown("---")
    st.caption("Blue Guard SIEM © 2025")

st.set_page_config("Blue-Guard SIEM", "🛡️", layout="wide")
st.markdown(f"""
<style>
  .stApp{{background:{DARK_BG};color:#f0f2f6;}}
  [data-testid=stSidebar]{{background:#1a1d24!important;border-right:1px solid #2a2e36;}}
  .stMetric{{background:#1a1d24;border-radius:8px;padding:15px;border-left:4px solid #4ba3c7;}}
  ::-webkit-scrollbar{{width:8px;}}::-webkit-scrollbar-track{{background:#1a1d24;}}
  ::-webkit-scrollbar-thumb{{background:#4ba3c7;border-radius:4px;}}
</style>
""", unsafe_allow_html=True)

tabs = st.tabs([
    "Overview", "Traffic", "Threats", "Suspicious IPs", "Blocked IPs", "Geography", "Advanced", "Report", "System"
])

all_figs = {}

# --- Overview ---
with tabs[0]:
    st.title("🛡️ Blue‑Guard SIEM — Overview")
    st.markdown("#### Executive Summary")
    logs = _run_sql("SELECT COUNT(*) as logs FROM logs").iloc[0,0]
    uips = _run_sql("SELECT COUNT(DISTINCT ip) as uips FROM logs").iloc[0,0]
    blocked = _run_sql("SELECT COUNT(*) as blocked FROM blocked_log").iloc[0,0]
    sus = _run_sql("SELECT COUNT(DISTINCT suspiciousIp) as sus FROM ip_suspicious").iloc[0,0]
    st.markdown(f"""
    - **Total log events:** {logs:,}
    - **Unique IPs:** {uips:,}
    - **Blocked IPs:** {blocked:,}
    - **Suspicious IPs:** {sus:,}
    """)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Logs", f"{logs:,}")
    col2.metric("Unique IPs", f"{uips:,}", delta=f"{sus/uips:.1%} suspicious" if uips else None)
    col3.metric("Blocked IPs", f"{blocked:,}")
    col4.metric("Suspicious IPs", f"{sus:,}")
    st.divider()
    st.subheader("🔥 Suspicious IPs per Day")
    days = st.slider("Days to show", 7, 60, 15, key="sus_days")
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
            ax.text(p.get_x() + p.get_width()/2, p.get_height() + max(df["cnt"])*0.02, f"{val:,}", ha="center", va="bottom", fontsize=10, color="w")
        ax.set(title="Suspicious IPs per Day", xlabel="Date", ylabel="Count")
        plt.xticks(rotation=45, ha="right", color="w")
        plt.yticks(color="w")
        ax.title.set_color("w")
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["suspicious_trend.png"] = fig
    st.markdown(get_csv_download_link(df, "suspicious_trend.csv"), unsafe_allow_html=True)

# --- Traffic ---
with tabs[1]:
    st.title("🌐 Traffic Patterns")
    min_day, max_day = _run_sql("SELECT MIN(DATE(time)), MAX(DATE(time)) FROM logs").iloc[0]
    date_range = st.date_input("Select date range", value=(pd.to_datetime(min_day), pd.to_datetime(max_day)), key="traffic_date_range")
    start, end = date_range if isinstance(date_range, (list, tuple)) else (min_day, max_day)
    st.subheader("Hourly/Weekly Heatmap")
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
        sns.heatmap(pivot, cmap="YlOrRd", linewidths=0.5, xticklabels=range(24), yticklabels=weekday_labels, ax=ax, cbar_kws={'label': 'Hits'})
        plt.title("Request Heatmap: Hourly Activity by Weekday", color="w", pad=20)
        plt.ylabel("Weekday", color="w")
        plt.xlabel("Hour of Day", color="w")
        plt.xticks(color="w")
        plt.yticks(color="w")
        fig.tight_layout()
        st.pyplot(fig)
        all_figs["traffic_heatmap.png"] = fig
    st.markdown(get_csv_download_link(df, "traffic_heatmap.csv"), unsafe_allow_html=True)
    st.subheader("🔗 Top URLs")
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
    st.markdown(get_csv_download_link(df, "top_urls.csv"), unsafe_allow_html=True)

# --- Threats ---
with tabs[2]:
    st.title("🚨 Threats & Suspicion")
    st.subheader("Suspicious IPs by Country")
    days = st.slider("Days", 7, 60, 30, key="country_days")
    top_n = st.slider("Top N Countries", 5, 20, 10, key="country_topn")
    latest_day = _run_sql("SELECT DATE(MAX(time)) AS d FROM logs").iloc[0, 0]
    if latest_day:
        start_day = (datetime.fromisoformat(latest_day) - timedelta(days=days)).strftime("%Y-%m-%d")
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
            fig_map = px.choropleth(df, locations="country", locationmode="country names",
                                    color="cnt", color_continuous_scale="Reds",
                                    title="Suspicious IPs by Country",
                                    template="plotly_dark")
            st.plotly_chart(fig_map, use_container_width=True)
            all_figs["suspicious_by_country_map.png"] = fig_map
            st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "suspicious_by_country.csv"), unsafe_allow_html=True)
    st.subheader("Reasons for Suspicion")
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
    st.markdown(get_csv_download_link(df, "suspicious_reasons.csv"), unsafe_allow_html=True)

# --- Suspicious IPs ---
with tabs[3]:
    st.title("🕵️ Suspicious IPs")
    search_ip = st.text_input("Search IP (partial match allowed)", key="susip_search")
    days = st.slider("Days to show", 1, 30, 7, key="susip_days")
    df = _run_sql(f"""
        SELECT suspiciousIp, MAX(time) last_seen, COUNT(*) events, GROUP_CONCAT(DISTINCT reason) reasons
        FROM ip_suspicious
        WHERE julianday(time) BETWEEN julianday('now', '-{days} day') AND julianday('now')
        GROUP BY suspiciousIp
        ORDER BY events DESC
        LIMIT 100
    """)
    if search_ip:
        df = df[df['suspiciousIp'].str.contains(search_ip)]
    st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "suspicious_ips.csv"), unsafe_allow_html=True)

# --- Blocked IPs ---
with tabs[4]:
    st.title("⛔ Blocked IPs")
    search_ip = st.text_input("Search Blocked IP", key="blockip_search")
    days = st.slider("Days to show", 1, 30, 7, key="blockip_days")
    df = _run_sql(f"""
        SELECT ip, detected_at, backend_blocked_at, detection_count, client_blocked_at, client_block_status
        FROM blocked_log
        WHERE julianday(backend_blocked_at) BETWEEN julianday('now', '-{days} day') AND julianday('now')
        ORDER BY detection_count DESC, ip
        LIMIT 100
    """)
    if search_ip:
        df = df[df['ip'].str.contains(search_ip)]
    st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "blocked_ips.csv"), unsafe_allow_html=True)

# --- Geography ---
with tabs[5]:
    st.title("🌍 Geography (Latest Day)")
    latest_day = _run_sql("SELECT DATE(MAX(time)) AS d FROM logs").iloc[0, 0]
    if latest_day:
        df = _run_sql(f"""
            SELECT country, COUNT(*) AS cnt
            FROM   logs
            WHERE  DATE(time) = '{latest_day}'
            GROUP  BY country
            ORDER  BY cnt DESC
        """)
        st.markdown("#### Top 10 Countries by Requests")
        if not df.empty:
            top10 = df.head(10)
            st.dataframe(top10, hide_index=True, use_container_width=True)
            fig_map = px.choropleth(df, locations="country", locationmode="country names",
                                    color="cnt", color_continuous_scale="Blues",
                                    title=f"Requests by Country ({latest_day})",
                                    template="plotly_dark")
            st.plotly_chart(fig_map, use_container_width=True)
            all_figs["country_hits_map.png"] = fig_map
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
                fig, ax = plt.subplots(facecolor=DARK_BG)
                sns.lineplot(data=df2, x="day", y="cnt", marker="o", ax=ax)
                ax.set(title=f"Daily Requests for {country_sel}", xlabel="Date", ylabel="Hits")
                plt.xticks(rotation=45, ha="right", color="w")
                plt.yticks(color="w")
                ax.title.set_color("w")
                fig.tight_layout()
                st.pyplot(fig)
                all_figs[f"country_trend_{country_sel}.png"] = fig
        st.markdown(get_csv_download_link(df, "country_hits.csv"), unsafe_allow_html=True)

# --- Advanced ---
with tabs[6]:
    st.title("🧠 Advanced Analytics")
    st.subheader("Advanced Log Summary")
    min_date, max_date = _run_sql("SELECT MIN(first_time_of_access), MAX(first_time_of_access) FROM advanced_logs").iloc[0]
    if pd.isnull(min_date) or pd.isnull(max_date):
        st.info("No advanced logs available.")
    else:
        date_range = st.date_input("Select date range", value=(pd.to_datetime(min_date), pd.to_datetime(max_date)), key="advanced_date_range")
        start, end = date_range if isinstance(date_range, (list, tuple)) else (min_date, max_date)
        df = _run_sql(f"""
            SELECT * FROM advanced_logs
            WHERE DATE(first_time_of_access) BETWEEN '{start}' AND '{end}'
            ORDER BY req_per_min DESC
            LIMIT 100
        """)
        if df.empty:
            st.info("No advanced logs in this date range.")
        else:
            st.dataframe(df, hide_index=True, use_container_width=True)
            st.markdown(get_csv_download_link(df, "advanced_logs.csv"), unsafe_allow_html=True)
    st.subheader("DDoS Incidents")
    df = _run_sql("""
        SELECT * FROM ddos_multiple_ip
        ORDER BY window_end DESC
        LIMIT 10
    """)
    st.dataframe(df, hide_index=True, use_container_width=True)
    st.markdown(get_csv_download_link(df, "ddos_incidents.csv"), unsafe_allow_html=True)

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
def render_reports_tab():
    st.title("📄 Comprehensive Security Analysis Report")
    st.caption(f"Full data span: {GLOBAL_MIN.date()} to {GLOBAL_MAX.date()}")

    # Date range selector
    report_range = st.date_input(
        "Select analysis period for comprehensive report",
        value=(GLOBAL_MIN.date(), GLOBAL_MAX.date()),
        min_value=GLOBAL_MIN.date(),
        max_value=GLOBAL_MAX.date(),
        key="comprehensive_report_range",
    )

    report_start = datetime.combine(report_range[0], datetime.min.time())
    report_end = datetime.combine(report_range[1], datetime.max.time())

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
            """, params=[report_start, report_end])

            # Suspicious IPs
            tables["Suspicious IPs"] = _run_sql("""
                SELECT suspiciousIp, time, reason, detection_count
                FROM ip_suspicious
                WHERE time BETWEEN ? AND ?
                ORDER BY detection_count DESC, time DESC
            """, params=[report_start, report_end])

            # Blocked IPs
            tables["Blocked IPs"] = _run_sql("""
                SELECT ip, detected_at, backend_blocked_at, detection_count,
                       client_blocked_at, client_block_status
                FROM blocked_log
                WHERE backend_blocked_at BETWEEN ? AND ?
                ORDER BY detection_count DESC
            """, params=[report_start, report_end])

            # Advanced logs
            tables["Advanced Behavioral Analysis"] = _run_sql("""
                SELECT ip, req_per_min, unique_urls, error_rate, avg_req_size_bytes,
                       method_ratio_post_by_get, first_time_of_access
                FROM advanced_logs
                WHERE first_time_of_access BETWEEN ? AND ?
                ORDER BY req_per_min DESC
            """, params=[report_start, report_end])

            # DDoS incidents
            tables["DDoS Incidents"] = _run_sql("""
                SELECT window_start, window_end, duration_s, total_hits,
                       unique_ips, peak_rps, inserted_at
                FROM ddos_multiple_ip
                WHERE window_start BETWEEN ? AND ?
                ORDER BY peak_rps DESC
            """, params=[report_start, report_end])

            # Hourly analysis
            tables["Hourly Activity Pattern"] = _run_sql("""
                SELECT strftime('%H', time) as hour, COUNT(*) as requests,
                       COUNT(DISTINCT ip) as unique_ips,
                       AVG(size) as avg_size
                FROM logs
                WHERE time BETWEEN ? AND ?
                GROUP BY hour
                ORDER BY hour
            """, params=[report_start, report_end])

            # Country analysis
            tables["Geographical Distribution"] = _run_sql("""
                SELECT country, COUNT(*) as requests,
                       COUNT(DISTINCT ip) as unique_ips,
                       AVG(size) as avg_request_size
                FROM logs
                WHERE time BETWEEN ? AND ?
                GROUP BY country
                ORDER BY requests DESC
            """, params=[report_start, report_end])

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


            # 6. Performance metrics
            total_requests = sum(df['requests'].sum() if 'requests' in df.columns 
                               else len(df) for df in tables.values())
            analyses["performance_analysis"] = [
                f"Total processed events: {total_requests:,}",
                f"Analysis period: {(report_end - report_start).days} days",
                f"Average daily events: {total_requests / max(1, (report_end - report_start).days):,.0f}",
                f"Peak hourly rate: {hourly_df['requests'].max() if not hourly_df.empty else 0:,} requests/hour"
            ]

            # Generate HTML report
            html_report = create_enhanced_html_report(
                report_start, report_end, tables, report_figs, analyses
            )

            # Save report
            filename = f"BlueGuard_Comprehensive_Report_{report_start.strftime('%Y%m%d')}_{report_end.strftime('%Y%m%d')}.html"
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
        # if selected_report:
        #     report_path = REPORTS_DIR / selected_report
        #     with open(report_path, "r", encoding="utf-8") as f:
        #         report_html = f.read()
        #     st.markdown(
        #         f"<iframe srcdoc='{report_html}' style='width:100%; height:600px; border:none;'></iframe>",
        #         unsafe_allow_html=True,
        #     )
        if selected_report:
            report_path = REPORTS_DIR / selected_report

            # read HTML
            with open(report_path, "r", encoding="utf-8") as f:
                report_html = f.read()

            # --- INLINE VIEW OF SELECTED REPORT -----------------------
            st.components.v1.html(
                report_html,          # raw HTML
                height=600,
                scrolling=True
            )

            # --- DOWNLOAD LINK ----------------------------------------
            with open(report_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            st.markdown(
                f'<a href="data:file/html;base64,{b64}" download="{selected_report}">⬇️ Download Report</a>',
                unsafe_allow_html=True
            )

            with open(report_path, "rb") as f:
                bytes_data = f.read()
                b64 = base64.b64encode(bytes_data).decode()
                href = f'<a href="data:file/html;base64,{b64}" download="{selected_report}">⬇️ Download Selected Report</a>'
                st.markdown(href, unsafe_allow_html=True)

# To use in your Streamlit app, call render_reports_tab() in your main page logic.

render_reports_tab()
# --- System ---
with tabs[8]:
    st.title("⚙️ System Info")
    st.write(f"**DB file:** `{DB_PATH}`  • {os.path.getsize(DB_PATH)/(1024**2):.2f} MB")
    st.write(f"**Log‑time span:** {LOG_MIN} → {LOG_MAX}")
    st.write(f"**Ingest‑time span:** {ING_MIN} → {ING_MAX}")

st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#a1a9b7;font-size:12px;'>"
    "Blue Guard SIEM © 2025 – Unified Multi-Tab Dashboard</div>",
    unsafe_allow_html=True,
)
