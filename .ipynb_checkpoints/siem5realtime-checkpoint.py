#!/usr/bin/env python
# coding: utf-8

# In[6]:


# import sqlite3
# from datetime import datetime
# from zoneinfo import ZoneInfo

# IST = ZoneInfo("Asia/Kolkata")
# now_ist = lambda: datetime.now(IST).isoformat()

# conn = sqlite3.connect("access_logs.db", check_same_thread=False)
# cur  = conn.cursor()

# # ── Tables ─────────────────────────────────────────────
# cur.execute("""
# CREATE TABLE IF NOT EXISTS logs (
#     id        INTEGER PRIMARY KEY AUTOINCREMENT,
#     ip        TEXT,
#     time      TEXT,
#     method    TEXT,
#     url       TEXT,
#     status    INTEGER,
#     size      INTEGER,
#     agent     TEXT,
#     ingest_ts TEXT            -- NEW: arrival timestamp in IST
# )
# """)

# cur.execute("""
# CREATE TABLE IF NOT EXISTS advanced_logs (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     ip TEXT,
#     req_per_min INTEGER,
#     unique_urls INTEGER,
#     error_rate REAL,
#     avg_req_size_bytes REAL,
#     method_ratio_post_by_get REAL,
#     first_time_of_access TEXT
# )
# """)

# cur.execute("""
# CREATE TABLE IF NOT EXISTS ip_eachHour_category (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     ip TEXT,
#     hour TEXT,
#     category TEXT
# )
# """)

# # ── Insert suspicious IP with ingest_ts ───────────────
# cur.executemany("""
# INSERT INTO logs (ip, time, method, url, status, size, agent, ingest_ts)
# VALUES (?, ?, ?, ?, ?, ?, ?, ?)
# """, [
#     ("10.0.0.99", "2025-06-21T01:00:00", "POST", "/login", 401, 1000, "MaliciousBot/1.0", now_ist()),
#     ("10.0.0.99", "2025-06-21T01:00:05", "POST", "/login", 403, 1200, "MaliciousBot/1.0", now_ist()),
#     ("10.0.0.99", "2025-06-21T01:00:10", "POST", "/admin", 401, 800, "MaliciousBot/1.0",  now_ist()),
# ])

# cur.execute("""
# INSERT INTO advanced_logs (
#     ip, req_per_min, unique_urls, error_rate,
#     avg_req_size_bytes, method_ratio_post_by_get, first_time_of_access
# ) VALUES (?, ?, ?, ?, ?, ?, ?)
# """, (
#     "10.0.0.99", 200, 20, 0.85, 10000, 5.0,
#     datetime(2025, 6, 21, 1, 0, tzinfo=IST).isoformat()
# ))

# cur.execute("""
# INSERT INTO ip_eachHour_category (ip, hour, category)
# VALUES (?, ?, ?)
# """, ("10.0.0.99", "1-2", "🔴 Credential Stuffing"))

# # ── Normal IP with ingest_ts ───────────────────────────
# cur.executemany("""
# INSERT INTO logs (ip, time, method, url, status, size, agent, ingest_ts)
# VALUES (?, ?, ?, ?, ?, ?, ?, ?)
# """, [
#     ("192.168.1.200", "2025-06-21T05:00:00", "GET", "/",      200, 250, "NormalUser/1.0", now_ist()),
#     ("192.168.1.200", "2025-06-21T05:00:02", "GET", "/about", 200, 300, "NormalUser/1.0", now_ist())
# ])

# cur.execute("""
# INSERT INTO advanced_logs (
#     ip, req_per_min, unique_urls, error_rate,
#     avg_req_size_bytes, method_ratio_post_by_get, first_time_of_access
# ) VALUES (?, ?, ?, ?, ?, ?, ?)
# """, (
#     "192.168.1.200", 2, 2, 0.0, 275, 0.5,
#     datetime(2025, 6, 21, 5, 0, tzinfo=IST).isoformat()
# ))

# cur.execute("""
# INSERT INTO ip_eachHour_category (ip, hour, category)
# VALUES (?, ?, ?)
# """, ("192.168.1.200", "5-6", "🟢 Normal"))

# conn.commit()
# conn.close()

# print("✅ Tables created/updated with ingest_ts, and sample rows inserted.")


# In[1]:


# #setting up automated updation of ip vs cuntry geolite databse
# import os
# import tarfile
# import requests

# class GeoLite2Updater:
#     def __init__(self, license_key, edition='GeoLite2-Country', extract_dir='./resources/geoliteCountry'):
#         self.license_key = license_key
#         self.edition = edition
#         self.extract_dir = extract_dir
#         self.download_path = f'{edition.lower()}.tar.gz'
#         self.final_path = os.path.join(self.extract_dir, f'{edition}.mmdb')
#         self.download_url = f'https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={license_key}&suffix=tar.gz'

#     def create_extract_dir(self):
#         os.makedirs(self.extract_dir, exist_ok=True)

#     def download_database(self):
#         print("📥 Downloading latest GeoLite2 database...")
#         response = requests.get(self.download_url, stream=True)
#         with open(self.download_path, 'wb') as f:
#             for chunk in response.iter_content(chunk_size=8192):
#                 f.write(chunk)

#     def extract_database(self):
#         print("📦 Extracting database...")
#         with tarfile.open(self.download_path, 'r:gz') as tar:
#             for member in tar.getmembers():
#                 if member.name.endswith('.mmdb'):
#                     tar.extract(member, path=self.extract_dir)
#                     extracted_path = os.path.join(self.extract_dir, member.name)
#                     os.renames(extracted_path, self.final_path)

#     def clean_up(self):
#         if os.path.exists(self.download_path):
#             os.remove(self.download_path)

#     def update_database(self):
#         self.create_extract_dir()
#         self.download_database()
#         self.extract_database()
#         self.clean_up()
#         print(f"✅ GeoLite2 database updated and ready at: {self.final_path}")

# #using class
# LICENSE_KEY = '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'  # Replace with your real key
# geo_updater = GeoLite2Updater(license_key=LICENSE_KEY)
# geo_updater.update_database()



# In[16]:


import sqlite3
import ipaddress
import geoip2.database

class GeoCountryUpdater:
    """
    Fill in the `country` column for any log rows that still have
    NULL or 'Unknown'.  Public IPs → GeoLite2 lookup,
    Private IPs → 'Private/Local Network'.
    """
    def __init__(self,
                 db_path: str = "access_logs.db",
                 mmdb_path: str = "./resources/geoliteCountry/GeoLite2-Country.mmdb"):
        self.db_path  = db_path
        self.mmdb_path = mmdb_path

    # ---------- helpers ----------
    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip.strip()).is_private
        except ValueError:
            return False

    # ---------- workhorse ----------
    def run(self):
        conn   = sqlite3.connect(self.db_path)
        cur    = conn.cursor()
        reader = geoip2.database.Reader(self.mmdb_path)

        # 1) make sure the column exists
        try:
            cur.execute("ALTER TABLE logs ADD COLUMN country TEXT")
        except sqlite3.OperationalError:
            pass  # already there

        # 2) grab ONLY rows that still need a value
        cur.execute("""
            SELECT rowid, ip
            FROM   logs
            WHERE  country IS NULL OR country = 'Unknown'
        """)
        rows = cur.fetchall()

        for rowid, ip in rows:
            ip_clean = ip.strip()

            if self._is_private(ip_clean):
                country = "Private/Local Network"
            else:
                try:
                    country = reader.country(ip_clean).country.name or "Unknown"
                except Exception:
                    country = "Unknown"

            cur.execute("UPDATE logs SET country = ? WHERE rowid = ?",
                        (country, rowid))

        conn.commit()
        conn.close()
        reader.close()
        print(f"✅ Enriched {len(rows)} rows that were Unknown/NULL.")



# In[21]:


import sqlite3
import pandas as pd
from functools import reduce
# Advanced features saved to 'advanced_logs' table in access_log.db
# TableName=advanced_logs; cols:ip,req_per_min,unique_urls,error_rate,avg_req_size_bytes,method_ratio_post_by_get,first_time_of_access


class AdvancedLogFeatureBuilder:
    def __init__(self, db_path='access_logs.db'):
        self.db_path = db_path
        self.conn = None
        self.df = None
        self.final_df = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)

    def load_data(self):
        """Load raw logs and prepare the dataframe safely."""
        self.df = pd.read_sql_query("SELECT * FROM logs", self.conn)

        # ip must be string
        self.df['ip'] = self.df['ip'].astype(str)

        # ── 🧹 PRE-CLEAN the 'time' column ──────────────────────────
        #  1) cast everything to str
        self.df['time'] = self.df['time'].astype(str)

        #  2) drop obviously bad entries ("0", "", None, etc.)
        self.df = self.df[self.df['time'].str.len() > 5]

        #  3) convert to datetime; invalid parses → NaT (errors="coerce")
        self.df['time'] = pd.to_datetime(self.df['time'], errors='coerce')

        #  4) drop any rows that still have NaT (optional but sensible)
        self.df = self.df.dropna(subset=['time']).reset_index(drop=True)


    def feature_requests_per_minute(self):
        self.df['minute'] = self.df['time'].dt.floor('T')
        req_per_min= self.df.groupby(['ip', 'minute']).size().groupby('ip').mean().reset_index()
        req_per_min.columns = ['ip', 'req_per_min']
        return req_per_min

    def feature_unique_urls(self):
        unique_urls = self.df.groupby('ip')['url'].nunique().reset_index()
        unique_urls.columns = ['ip', 'unique_urls']
        return unique_urls

    def feature_error_rate(self):
        self.df['is_error'] = self.df['status'].astype(str).str.startswith(('4', '5'))
        error_rate = self.df.groupby('ip')['is_error'].mean().reset_index()
        error_rate.columns = ['ip', 'error_rate']
        return error_rate

    def feature_avg_req_size_bytes(self):
        avg_req_size_bytes = self.df.groupby('ip')['size'].mean().reset_index()
        avg_req_size_bytes.columns = ['ip', 'avg_req_size_bytes']
        return avg_req_size_bytes

    def feature_method_ratio_post_by_get(self):
        methods = self.df[self.df['method'].isin(['GET', 'POST'])]
        method_counts = methods.groupby(['ip', 'method']).size().unstack(fill_value=0)

        if 'POST' not in method_counts.columns:
            method_counts['POST'] = 0
        if 'GET' not in method_counts.columns:
            method_counts['GET'] = 0

        method_counts['method_ratio_post_by_get'] = method_counts['POST'] / (method_counts['GET'] + 1e-6)
        method_ratio_post_by_get = method_counts[['method_ratio_post_by_get']].reset_index()
        return method_ratio_post_by_get

    def feature_first_access_time(self):
        first_time = self.df.groupby('ip')['time'].min().reset_index()
        first_time.columns = ['ip', 'first_time_of_access']
        return first_time

    def merge_features(self):
        features = [
            self.feature_requests_per_minute(),
            self.feature_unique_urls(),
            self.feature_error_rate(),
            self.feature_avg_req_size_bytes(),
            self.feature_method_ratio_post_by_get(),
            self.feature_first_access_time()
        ]
        self.final_df = reduce(lambda left, right: pd.merge(left, right, on='ip', how='outer'), features)
        self.final_df = self.final_df.fillna(0)
        # ─── NEW: force datetime column → plain ISO string ──────────
        if 'first_time_of_access' in self.final_df.columns:
            self.final_df['first_time_of_access'] = (
                self.final_df['first_time_of_access']
                .astype(str)                              # ← cast fixes binding error
            )
        
    def save_to_database(self, table_name='advanced_logs'):
        self.final_df.to_sql(table_name, self.conn, if_exists='replace', index=False)
        print(f"✅ Advanced features saved to '{table_name}' table.")

    def preview(self, limit=10):
        preview_df = pd.read_sql_query(f"SELECT * FROM advanced_logs LIMIT {limit}", self.conn)
        print("📝 Columns:", list(preview_df.columns))
        print("\n📊 First 10 rows:")
        print(preview_df)

    def close(self):
        if self.conn:
            self.conn.close()

    def run(self, preview=False):
        self.connect()
        self.load_data()
        self.merge_features()
        self.save_to_database()
        if preview:
            self.preview()
        self.close()

#using class
builder = AdvancedLogFeatureBuilder('access_logs.db')
# builder.run(preview=True)


# In[166]:


# Table 'ip_eachHour' with 24-hour hit distribution saved in access_logs.db itself

import sqlite3
import pandas as pd

class HourlyHitAnalyzer:
    def __init__(self, db_path='access_logs.db'):
        self.db_path = db_path
        self.conn = None
        self.df = None
        self.pivot = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)

    def load_logs(self):
        self.df = pd.read_sql_query("SELECT ip, time FROM logs", self.conn)
        self.df['time'] = pd.to_datetime(self.df['time'], errors='coerce')
        self.df['hour'] = self.df['time'].dt.hour

    def calculate_hits_per_hour(self):
        hits = self.df.groupby(['ip', 'hour']).size().reset_index(name='hits')
        self.pivot = hits.pivot(index='ip', columns='hour', values='hits').fillna(0).astype(int)

    def rename_columns(self):
        new_col_names = {i: f'{i}-{i+1}' for i in range(24)}
        self.pivot.rename(columns=new_col_names, inplace=True)
        self.pivot.reset_index(inplace=True)

    def save_to_database(self, table_name='ip_eachHour'):
        self.pivot.to_sql(table_name, self.conn, if_exists='replace', index=False)
        print(f"✅ Table '{table_name}' with 24-hour hit distribution saved in {self.db_path}")

    def preview_table(self, table_name='ip_eachHour', limit=10):
        df_preview = pd.read_sql_query(f"SELECT * FROM {table_name} LIMIT {limit}", self.conn)
        print(f"📊 Sample from '{table_name}' table:")
        print(df_preview)

    def close(self):
        if self.conn:
            self.conn.close()

    def run_analysis(self, preview=False):
        self.connect()
        self.load_logs()
        self.calculate_hits_per_hour()
        self.rename_columns()
        self.save_to_database()
        if preview:
            self.preview_table()
        self.close()


#using class
analyzer = HourlyHitAnalyzer('access_logs.db')
# analyzer.run_analysis(preview=True)


# In[167]:


#created new table ip_eachHour_category with cols: ip,hour,category
import sqlite3
import pandas as pd

class EachHourCategoryClassifier:
    def __init__(self, db_path='access_logs.db'):
        self.db_path = db_path
        self.conn = None
        self.df = None
        self.result_df = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)

    def load_data(self):
        self.df = pd.read_sql_query("SELECT * FROM ip_eachHour", self.conn)

    def classify(self, hits):
        if hits <= 1:
            return 'Idle / Minimal'
        elif hits <= 50:
            return 'Casual Human'
        elif hits <= 200:
            return 'Active Human'
        elif hits <= 1000:
            return 'Automation / Crawler'
        elif hits <= 3000:
            return 'Aggressive Bot'
        elif hits <= 5000:
            return 'Credential Stuffing / Vulnerability Scans'
        elif hits <= 10000:
            return 'DoS Behavior'
        else:
            return 'DoS Botnet / Amplification'

    def melt_and_classify(self):
        melted_df = self.df.melt(id_vars='ip', var_name='hour', value_name='hits')
        melted_df['category'] = melted_df['hits'].apply(self.classify)
        self.result_df = melted_df[['ip', 'hour', 'category']]

    def save_to_db(self, table_name='ip_eachHour_category'):
        self.result_df.to_sql(table_name, self.conn, if_exists='replace', index=False)
        print(f"✅ Hour-wise category table saved to '{table_name}'.")

    def preview(self, limit=48):
        preview_df = pd.read_sql_query("SELECT * FROM ip_eachHour_category LIMIT ?", self.conn, params=(limit,))
        print("📊 Sample from 'ip_eachHour_category':")
        print(preview_df)


    def close(self):
        if self.conn:
            self.conn.close()

    def run(self, preview=False):
        self.connect()
        self.load_data()
        self.melt_and_classify()
        self.save_to_db()
        if preview:
            self.preview()
        self.close()

#using class
classifier = EachHourCategoryClassifier('access_logs.db')
# classifier.run(preview=True)


# In[1]:


# ────────────────────────────────────────────────────────────────
# Create a table to log every *multi-IP-per-second* swarm incident
# ────────────────────────────────────────────────────────────────
import sqlite3

def init_ddos_table(db_path="access_logs.db"):
    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS ddos_multiple_ip (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            -- ISO-8601 timestamps mark the exact second bucket
            window_start  TEXT,
            window_end    TEXT,
            duration_s    INTEGER,       -- currently always 1 s
            total_hits    INTEGER,       -- #requests seen in that second
            unique_ips    INTEGER,       -- how many different IPs joined
            peak_rps      INTEGER,       -- same as total_hits for 1-s window
            inserted_at   TEXT DEFAULT (datetime('now'))
        );
        """)
    print("✅ ddos_multiple_ip ready")

# call it once
init_ddos_table()


# In[2]:


# ────────────────────────────────────────────────────────────────
# Real-time multi-IP per-second burst detector
# ────────────────────────────────────────────────────────────────
from collections import deque
from datetime import datetime, timedelta
import sqlite3

class MultiIPDDoSDetector:
    """
    Watches a sliding 1-second window of raw log events (ip, ts).
    When the window exceeds BOTH:
        • hits_thr  – total requests
        • uniq_thr  – distinct IPs
    → (1) write an incident row to ddos_multiple_ip
      (2) call alert_callback(set_of_ips, incident_dict)
    A cooldown stops duplicate alerts during the same attack.
    """
    def __init__(
        self,
        db_path: str,
        alert_callback,            # function that handles swarm IPs
        window_s:   int = 1,       # analysis bucket size (seconds)
        hits_thr:   int = 800,     # tweak for your traffic baseline
        uniq_thr:   int = 120,     #    "
        cooldown_s: int = 60       # min seconds between incidents
    ):
        # config
        self.db_path    = db_path
        self.alert_cb   = alert_callback
        self.window_s   = window_s
        self.hits_thr   = hits_thr
        self.uniq_thr   = uniq_thr
        self.cooldown_s = cooldown_s
        # runtime state
        self.events        = deque()      # stores (timestamp, ip)
        self.last_alert_ts = None         # last incident time

    # ------------------------------------------------------------------
    # ingest() MUST be called for **every** raw log line you receive
    # ------------------------------------------------------------------
    def ingest(self, ip: str, ts: datetime):
        self.events.append((ts, ip))

        # drop events older than our sliding window
        cutoff = ts - timedelta(seconds=self.window_s)
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

        # after updating the window → check thresholds
        self._maybe_fire(ts)

    # ------------------------------------ internal helpers --------
    def _maybe_fire(self, now: datetime):
        total_hits = len(self.events)
        uniq_ips   = len({ip for _, ip in self.events})

        # skip if thresholds not met
        if total_hits < self.hits_thr or uniq_ips < self.uniq_thr:
            return

        # skip if still in cooldown
        if self.last_alert_ts and (now - self.last_alert_ts).total_seconds() < self.cooldown_s:
            return

        # build incident summary
        incident = dict(
            window_start = (now - timedelta(seconds=self.window_s)).isoformat(),
            window_end   = now.isoformat(),
            duration_s   = self.window_s,
            total_hits   = total_hits,
            unique_ips   = uniq_ips,
            peak_rps     = total_hits            # = total_hits for 1-s window
        )
        # 1️⃣ store in SQLite
        self._write_incident(incident)
        # 2️⃣ remember last fire time
        self.last_alert_ts = now
        # 3️⃣ collect participating IPs
        swarm_ips = {ip for _, ip in self.events}
        print(f"🌊 DDoS burst logged! hits={total_hits} uniq={uniq_ips}")
        # 4️⃣ hand off to the pipeline (adds to ip_suspicious + alerts)
        self.alert_cb(swarm_ips, incident)

    def _write_incident(self, row: dict):
        """Insert incident row into ddos_multiple_ip."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO ddos_multiple_ip
                (window_start, window_end, duration_s,
                 total_hits, unique_ips, peak_rps)
                VALUES (:window_start,:window_end,:duration_s,
                        :total_hits,:unique_ips,:peak_rps)
            """, row)


# In[168]:


# #configuration
# Updated Config class with Together.ai API
class Config:
    DB_PATH = "access_logs.db"
    OPENAI_API_KEY = "6d5f9d8edb25a1743e5272f75f52a818ead6a95635e57b122118fb82d754c697"
    SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_SENDER = "aashij971@gmail.com"
    EMAIL_PASSWORD = "bbff hzuj lczj bhmy"
    EMAIL_RECEIVER = "aashijainbid@gmail.com"



# In[53]:


import sqlite3
import pandas as pd

class SuspiciousIPDetector:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)

    def get_suspicious_ips(self):
        # Thresholds
        MIN_req_per_min= 10
        MIN_UNIQUE_URLS = 15
        MAX_ERROR_RATE = 0.2
        MAX_avg_req_size_bytes = 10000
        MAX_method_ratio_post_by_get = 3.0
        SCORE_THRESHOLD = 5  # Minimum weighted score to consider suspicious

        # High-risk behavior categories
        suspicious_categories = [
            '🟠 Automation / Crawlers', '🔴 Aggressive Bot',
            '🔴 Credential Stuffing', '🔴 Vulnerability Scans',
            '🔴 DoS Behavior', '🚨 DoS Botnets / Amplification'
        ]

        # 🧠 Category-based IPs
        category_query = f"""
            SELECT DISTINCT ip FROM ip_eachHour_category
            WHERE category IN ({','.join(['?']*len(suspicious_categories))})
        """
        category_df = pd.read_sql_query(category_query, self.conn, params=suspicious_categories)

        # 🧠 Threshold + weighted score logic
        adv_df = pd.read_sql_query("SELECT * FROM advanced_logs", self.conn)
        if adv_df.empty:
            return category_df['ip'].tolist()  # return only category-based if advanced is empty

        # adv_df['hour'] = pd.to_datetime(adv_df['first_time_of_access']).dt.hour
        # Parse strings → pandas datetimes
        adv_df['first_time_of_access'] = pd.to_datetime(adv_df['first_time_of_access'])

        # Safely ensure every stamp is Asia/Kolkata
        adv_df['first_time_of_access'] = adv_df['first_time_of_access'].apply(
                lambda ts: ts.tz_localize('Asia/Kolkata')        # naive → attach IST
               if ts.tzinfo is None                  # already aware → convert
               else ts.tz_convert('Asia/Kolkata')
        )

        # Now extract the local hour
        adv_df['hour'] = adv_df['first_time_of_access'].dt.hour


        is_odd_hour = adv_df['hour'] % 2 != 0

        # Assign weighted score per condition
        adv_df['score'] = 0
        adv_df.loc[adv_df['req_per_min'] > MIN_req_per_min, 'score'] += 1.5
        adv_df.loc[adv_df['unique_urls'] > MIN_UNIQUE_URLS, 'score'] += 1.5
        adv_df.loc[adv_df['error_rate'] > MAX_ERROR_RATE, 'score'] += 2
        adv_df.loc[adv_df['avg_req_size_bytes'] > MAX_avg_req_size_bytes, 'score'] += 1
        adv_df.loc[adv_df['method_ratio_post_by_get'] > MAX_method_ratio_post_by_get, 'score'] += 2
        adv_df.loc[is_odd_hour, 'score'] += 1

        threshold_ips = adv_df[adv_df['score'] >= SCORE_THRESHOLD]['ip'].tolist()
        category_ips = category_df['ip'].tolist()

        return list(set(threshold_ips + category_ips))


# In[17]:


#ml based (isolation forest) suspicious ip detector
from sklearn.ensemble import IsolationForest

class MLBasedAnomalyDetector:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)

    def get_features(self):
        df = pd.read_sql_query("SELECT * FROM advanced_logs", self.conn)
        X = df[["req_per_min", "unique_urls", "error_rate", "avg_req_size_bytes", "method_ratio_post_by_get"]]
        return df["ip"], X

    def detect_anomalies(self):
        ips, X = self.get_features()
        if X.empty:
            return []                     # ⬅ early-return, avoids IsolationForest crash
        model = IsolationForest(contamination=0.05, random_state=42)
        preds = model.fit_predict(X)
        return ips[preds == -1].tolist()



# In[37]:


import ipaddress   
class IPContextFetcher:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def get_ip_context(self, ip):
        """
        Return a context dict for the given IP.
        Never returns None – at minimum {'ip': ip}.
        """
        context = {"ip": ip}

        # ── 1) advanced_logs  ─────────────────────────────────
        adv_df = pd.read_sql_query(
            "SELECT * FROM advanced_logs WHERE ip = ?",
            self.conn, params=[ip]
        )
        if not adv_df.empty:
            adv = adv_df.iloc[0].to_dict()
            context.update({
                "req_per_min":            adv.get("req_per_min", "n/a"),
                "error_rate (4xx+5xx)/total req": adv.get("error_rate", "n/a"),
                "unique_urls":            adv.get("unique_urls", "n/a"),
                "avg_req_size_bytes":     adv.get("avg_req_size_bytes", "n/a"),
                "method_ratio_post_by_get": adv.get("method_ratio_post_by_get", "n/a"),
                "first_time_of_access":   adv.get("first_time_of_access", "n/a"),
            })
        else:
            # fill missing numeric fields with "n/a"
            context.update({
                "req_per_min": "n/a",
                "error_rate (4xx+5xx)/total req": "n/a",
                "unique_urls": "n/a",
                "avg_req_size_bytes": "n/a",
                "method_ratio_post_by_get": "n/a",
                "first_time_of_access": "n/a",
            })

        # ── 2) Top 5 URLs  ────────────────────────────────────
        urls_df = pd.read_sql_query(
            "SELECT url FROM logs WHERE ip = ?", self.conn, params=[ip]
        )
        context["top_5_urls"] = (
            urls_df["url"].value_counts().head(5).index.tolist()
            if not urls_df.empty else []
        )

        # ── 3) Hourly categories  ─────────────────────────────
        hourly_df = pd.read_sql_query(
            "SELECT hour, category FROM ip_eachHour_category WHERE ip = ?",
            self.conn, params=[ip]
        )
        context["categories_by_hour"] = hourly_df.to_dict(orient="records")

        # ── 4) Country  ───────────────────────────────────────
        country_df = pd.read_sql_query("""
            SELECT country
            FROM logs
            WHERE ip = ?
              AND country IS NOT NULL
              AND country <> ''
            LIMIT 1;
        """, self.conn, params=[ip])

        if not country_df.empty:
            context["country"] = country_df["country"].iloc[0]
        else:
            context["country"] = (
                "Private/Local Network" if self._is_private(ip) else "Unknown"
            )

        return context


# In[172]:


# #propmt generator and gen ai interface
# Updated GenAIExplainer using Together.ai for LLaMA models
import requests

class GenAIExplainer:
    def __init__(self, api_key, model_name="meta-llama/Llama-3-70b-chat-hf"):
        self.api_key = api_key
        self.model_name = model_name
        self.api_url = "https://api.together.xyz/v1/chat/completions"

    def generate_prompt(self, data):
        hourly_summary = "\n".join([f"Hour {row['hour']}: {row['category']}" for row in data['categories_by_hour']])
        return f"""
    IP: {data['ip']}
    Country: {data['country']}
    Request Rate: {data['req_per_min']} req/min
    Error Rate: {data['error_rate']}
    Unique URLs: {data['unique_urls']}
    Avg Request Size: {data['avg_req_size_bytes']}
    Method Ratio Post/Get: {data['method_ratio_post_by_get']}
    First Access Time: {data['first_time']}
    Top URLs: {', '.join(data['top_5_urls'])}
    Hourly Categories:\n{hourly_summary}
    Explain this behavior.
    """


    def get_explanation(self, prompt):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 500
        }
        response = requests.post(self.api_url, headers=headers, json=payload)
        return response.json()['choices'][0]['message']['content']



# In[8]:


#alert sender (email+slack)
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart 

class AlertSender:
    def __init__(self, config):
        self.config = config

    def send_email(self, subject, body):
        try:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.config.EMAIL_SENDER
            msg['To'] = self.config.EMAIL_RECEIVER
            with smtplib.SMTP(self.config.SMTP_SERVER, self.config.SMTP_PORT) as server:
                server.starttls()
                server.login(self.config.EMAIL_SENDER, self.config.EMAIL_PASSWORD)
                server.sendmail(self.config.EMAIL_SENDER, [self.config.EMAIL_RECEIVER], msg.as_string())
            print("✅ Email alert sent")
        except Exception as e:
            
            print(f"❌ Email error: {e}")

    def send_slack_alert(self, message):
        try:
            resp = requests.post(self.config.SLACK_WEBHOOK_URL, json={"text": message})
            if resp.status_code != 200:
                print(f"❌ Slack error: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"❌ Slack error: {e}")

        # ─────────────────────────────────────────────────────────────
    # NEW  ▸ send a single digest for an entire DDoS burst
    # ----------------------------------------------------------------
    def send_burst(self, incident: dict, ip_list: list[str]):
        """
        incident = {'window_start', 'window_end', 'total_hits',
                    'unique_ips', 'duration_s', 'peak_rps', …}
        ip_list  = list of all participating IPs (already sorted)
        rps means request per sec
        """
        subject = (f"🚨 DDoS burst: {incident['unique_ips']} IPs, "
                   f"{incident['total_hits']} reqs in {incident['duration_s']} s")

        body = (
            f"🌊 DDoS detected {incident['window_start']} → {incident['window_end']}\n"
            f"• Total hits : {incident['total_hits']}\n"
            f"• Unique IPs : {incident['unique_ips']}\n"
            f"• Peak RPS   : {incident['peak_rps']}\n\n"
            "Top offender IPs (first 30):\n"
            + "\n".join(f"  • {ip}" for ip in ip_list[:30])
            + ("\n… (truncated)" if len(ip_list) > 30 else "")
        )

        # one SMTP login + one Slack POST
        self.send_email(subject, body)
        self.send_slack_alert(f"{subject}\n{body}")


    def send(self, ip, context, explanation):
        """
        Build the e-mail / Slack message for a suspicious IP.
        • Works even if the context dict is minimal (e.g. only {"ip": ip}).
        """
        subject = f"🚨 Suspicious IP Detected: {ip}"

        # 1️⃣  All context fields except the bulky hour table
        context_text = "\n".join(
            f"{k}: {v}" for k, v in context.items() if k != "categories_by_hour"
        )

        # 2️⃣  Hourly categories ◀ safe fallback when key is missing
        cat_rows = context.get("categories_by_hour", [])   # ← returns [] if key absent
        category_text = "\n".join(
            f"  Hour {row['hour']} ➤ {row['category']}" for row in cat_rows
        ) or "n/a"

        # 3️⃣  Final body
        body = f"""📌 CONTEXT:
{context_text}

⏱ Hourly Categories:
{category_text}

🧠 EXPLANATION:
{explanation}"""

        # 4️⃣  Send alerts
        self.send_email(subject, body)
        self.send_slack_alert(f"{subject}\n{body}")

        # 5️⃣  Debug print
        print("📤 Preparing to send alert:")
        print("Context:", context)
        print("Explanation:", explanation)



# In[24]:


import sqlite3
from datetime import datetime
from typing import Optional
import threading
from datetime import datetime
from zoneinfo import ZoneInfo 
import pandas as pd
from collections import defaultdict          # NEW ➜ per‑IP locking

_ip_locks = defaultdict(threading.Lock)      # NEW ➜ one Lock object per unique IP

class AnomalyExplainerPipeline:
    IST = ZoneInfo("Asia/Kolkata")
    def __init__(self, config):
        self.config = config
        self.detector = SuspiciousIPDetector(config.DB_PATH)
        self.ml_detector = MLBasedAnomalyDetector(config.DB_PATH)
        self.fetcher = IPContextFetcher(config.DB_PATH)
        self.alert = AlertSender(config)
        # ⚙️ Prepare GenAI explainer for future LLaMA integration (disabled in test mode)
        # self.genai = GenAIExplainer(api_key=config.LLAMA_API_KEY)


    def is_ip_previously_flagged(self, ip):
        conn = sqlite3.connect(self.config.DB_PATH, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM ip_suspicious WHERE suspiciousIp = ?", (ip,))
        result = cursor.fetchone()
        conn.close()
        return result is not None


    def block_ip(self, ip: str, *, detected_at: str | None = None) -> None:
        """
        Block an IP and record:
        • detected_at = arrival-time (in IST) when the detector fired
        • backend_blocked_at  = block moment (in IST) when block_ip called
        If detected_at is None we look up the newest logs.ingest_ts for that IP.
        """

        conn   = sqlite3.connect(self.config.DB_PATH, check_same_thread=False)
        cur    = conn.cursor()

        # fallback: newest ingest_ts for this IP
        if detected_at is None:
            cur.execute(
            "SELECT ingest_ts FROM logs WHERE ip=? ORDER BY ingest_ts DESC LIMIT 1",
            (ip,)
            )
            row          = cur.fetchone()
            detected_at  = row[0] if row else datetime.now(self.IST).isoformat()

        backend_blocked_at = datetime.now(self.IST).isoformat()  # LOCAL (IST)

        print(f"🚫 Blocking {ip} | detected_at={detected_at} | backend_locked_at={backend_blocked_at}")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked_log (
            ip TEXT PRIMARY KEY,
            detected_at TEXT,
            backend_blocked_at  TEXT,
            detection_count INTEGER DEFAULT 1
        )
        """)
        cur.execute("""
            INSERT INTO blocked_log (ip, detected_at, backend_blocked_at, detection_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE
                SET backend_blocked_at      = excluded.backend_blocked_at,
                detection_count = detection_count + 1
        """, (ip, detected_at, backend_blocked_at))

        conn.commit()
        conn.close()


    def insert_suspicious_ip(self, ip: str, forced_reason: str | None = None):
        conn = sqlite3.connect(self.config.DB_PATH, check_same_thread=False)
        cursor = conn.cursor()

        # table may not exist on first run → create lazily
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_suspicious (
                suspiciousIp   TEXT PRIMARY KEY,
                time           TEXT,
                reason         TEXT,
                detection_count INTEGER DEFAULT 0
            );
        """)

        # Decide the "reason" field
        if forced_reason:
            reason = forced_reason                       # e.g. "DDoS burst"
        else:
            # find most common behaviour category for that IP
            category_df = pd.read_sql_query("""
                SELECT category, COUNT(*) AS cnt
                FROM   ip_eachHour_category
                WHERE  ip = ?
                GROUP BY category
                ORDER BY cnt DESC
                LIMIT 1;
            """, conn, params=[ip])
            top_cat = category_df['category'][0] if not category_df.empty else "Unknown Category"

            # figure out which engine(s) flagged the IP
            rule_ips = set(self.detector.get_suspicious_ips())
            ml_ips   = set(self.ml_detector.detect_anomalies())
            if ip in rule_ips and ip in ml_ips:
                src = "via Rule + ML"
            elif ip in rule_ips:
                src = "via Rule"
            elif ip in ml_ips:
                src = "via ML"
            else:
                src = "via Unknown"

            reason = f"{top_cat} ({src})"

        now = datetime.now(self.IST).isoformat()   # e.g. 2025-06-27T18:25:00+05:30

        # INSERT if new, otherwise UPDATE timestamp & increment counter
        cursor.execute("""
            INSERT OR IGNORE INTO ip_suspicious (suspiciousIp, time, reason, detection_count)
            VALUES (?, ?, ?, 0);
        """, (ip, now, reason))
        cursor.execute("""
            UPDATE ip_suspicious
            SET time = ?, reason = ?, detection_count = detection_count + 1
            WHERE suspiciousIp = ?;
        """, (now, reason, ip))
        conn.commit()
        conn.close()
        print(f"✅ ip_suspicious ⇢ {ip} • {reason}")

    
        # ────────────────────────────────────────────────────────────
    # DDoS burst callback  →  ONE digest alert, then per-IP DB/block
    # ────────────────────────────────────────────────────────────
    def handle_ddos_ips(self, ip_set: set[str], incident: dict):
        ip_list = sorted(ip_set)

        # 1️⃣  ONE summary e-mail / Slack
        self.alert.send_burst(incident, ip_list)

        # 2️⃣  Still record and block each IP, but NO per-IP e-mails
        for ip in ip_list:
            self.insert_suspicious_ip(ip, forced_reason="DDoS burst")
            # 5️⃣ simulate block
            self.block_ip(ip)


    def _last_alert_time(self, ip: str):
        """
        Return the last time this IP was inserted into ip_suspicious,
        always as a timezone-aware datetime in Asia/Kolkata.
        """
        conn = sqlite3.connect(self.config.DB_PATH, check_same_thread=False)
        row  = conn.execute(
            "SELECT time FROM ip_suspicious WHERE suspiciousIp = ?",
            (ip,)
        ).fetchone()
        conn.close()

        if not row:
            return None                                   # never alerted

        ts_str = row[0]

        # Convert string → datetime.  If the stored string already has
        # “+05:30” it comes out zone-aware; otherwise we pin it to IST.
        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:                        # naive → attach IST
                dt = dt.replace(tzinfo=self.IST)
        except Exception:                                # malformed → use now
            dt = datetime.now(self.IST)

        return dt

    def process_single_ip(self, ip):
        # 🔒 per‑IP mutex
        lock = _ip_locks[ip]
        with lock:

            # skip if we alerted in the last 30 min
            last_alert = self._last_alert_time(ip)
            if last_alert and (datetime.now(self.IST) - last_alert).total_seconds() < 1800:
                return

            # run detectors
            rule_ips = set(self.detector.get_suspicious_ips())
            ml_ips   = set(self.ml_detector.detect_anomalies())

            if ip in rule_ips or ip in ml_ips:
                now_iso = datetime.now(self.IST).isoformat()

                # decide context: full on first sighting, minimal on repeats
                context = ({"info": "Previously flagged"} 
                           if last_alert else
                           self.fetcher.get_ip_context(ip))

                # record / refresh
                self.insert_suspicious_ip(ip)
                self.block_ip(ip, detected_at=now_iso)

                # async alert
                threading.Thread(
                    target=self._async_alert,
                    args=(ip, context, rule_ips, ml_ips),
                    daemon=True
                ).start()


    def _async_alert(self, ip, context, rule_ips, ml_ips):
         # ✅ Generate explanation
        # 💬 LLaMA GenAI response (future): Replace static explanation with LLaMA output
        # prompt = self.alert.genai.generate_prompt(context)  # ⬅️ Uncomment if using GenAI
        # explanation = self.alert.genai.get_explanation(prompt)  # ⬅️ Will fetch LLaMA-powered analysis
        
        explanation = (
            f"Rule-based: {'Yes' if ip in rule_ips else 'No'}, "
            f"ML-based: {'Yes' if ip in ml_ips else 'No'} "
            "📌 Note: GenAI skipped"
        )
        self.alert.send(ip, context, explanation)


# In[18]:


from datetime import datetime, timedelta          # ← keep
from zoneinfo import ZoneInfo                     # 💠 NEW
import time, sqlite3, pandas as pd

IST = ZoneInfo("Asia/Kolkata")                    # 💠 NEW

def simulate_realtime_stream(pipeline, interval: int = 1):
    """
    Wakes every `interval` seconds:
      • Feeds the last 2-second slice of logs into the DDoS detector
      • Runs rule+ML on previously unseen IPs
    """
    global seen_ips
    seen_ips = set()
    print("🚀 Real-time suspicious-IP & DDoS monitoring started")

    ddos_watcher = MultiIPDDoSDetector(
        pipeline.config.DB_PATH,
        alert_callback=pipeline.handle_ddos_ips
    )

    while True:
        try:
            # 1️⃣ ── Pull last 2-second burst (using ingest_ts) ─────────
            now_ist        = datetime.now(IST)
            window_start   = (now_ist - timedelta(seconds=2)).isoformat()

            with sqlite3.connect(pipeline.config.DB_PATH) as conn:
                recent = pd.read_sql_query(
                    "SELECT ip, ingest_ts AS ts "
                    "FROM   logs "
                    "WHERE  ingest_ts >= ?",
                    conn, params=(window_start,)
                )

            # feed each row to the 1-sec burst detector
            for _, row in recent.iterrows():
                try:
                    ts = datetime.fromisoformat(row['ts'])     # 💠 string → datetime
                except Exception:
                    ts = datetime.now(IST)                     # fallback
                ddos_watcher.ingest(ip=row['ip'], ts=ts)

            # 2️⃣ ── Rule+ML for brand-new IPs ───────────────────────
            conn = sqlite3.connect(pipeline.config.DB_PATH)
            all_ips_df = pd.read_sql_query("SELECT DISTINCT ip FROM logs", conn)
            conn.close()

            new_ips = [ip for ip in all_ips_df['ip'] if ip not in seen_ips]
            for ip in new_ips:
                print(f"\n📡 [New IP Detected] {ip}")
                pipeline.process_single_ip(ip)
                seen_ips.add(ip)

            time.sleep(interval)                                 # 3️⃣ wait

        except Exception as e:
            print(f"❌ Error in real-time loop: {e}")
            time.sleep(interval)




# In[40]:


# # To use:
# pipeline = AnomalyExplainerPipeline(Config())
# simulate_one_batch(pipeline)


# In[4]:


#pinting access_logs.db to verify
import sqlite3

def print_all_tables(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cursor = conn.cursor()

    # Fetch all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()

    for (table_name,) in tables:
        print(f"\n📂 Table: {table_name}")
        
        # Get column names
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"🔸 Columns: {columns}")
        
        # Fetch and print all rowsx
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(dict(zip(columns, row)))
        else:
            print("⚠️ No data in this table.")

    conn.close()

# Use the function
print_all_tables("access_logs.db")



# In[43]:


# import sqlite3

# def clear_all_tables(db_path="access_logs.db"):
#     conn = sqlite3.connect(db_path)
#     cursor = conn.cursor()

#     # Get list of all table names
#     cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
#     tables = cursor.fetchall()

#     for (table_name,) in tables:
#         print(f"🧹 Clearing table: {table_name}")
#         cursor.execute(f"DELETE FROM {table_name}")

#     conn.commit()
#     conn.close()
#     print("✅ All tables cleared successfully.")

# clear_all_tables()


# In[7]:


# ───────────────────────────────────────────────────────────────
#  Blue Guard – Plots (Jupyter / .py friendly)
#  Updated: fixes trend‑line crash & browser bar chart
# ───────────────────────────────────────────────────────────────
import matplotlib.pyplot as plt
import pandas as pd
import sqlite3
import seaborn as sns
import pathlib
import numpy as np
from datetime import datetime, timedelta
from ipywidgets import interact, widgets
import re

# ── Paths & global style ───────────────────────────────────────
BASE_DIR   = pathlib.Path().absolute()
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)

sns.set_theme(style="whitegrid", palette="viridis")
plt.style.use("ggplot")
plt.rcParams["figure.figsize"] = (12, 6)
plt.rcParams["font.size"]      = 12

# ── DB helper ──────────────────────────────────────────────────
def _run_sql(db_path: str, query: str, **kw) -> pd.DataFrame:
    return pd.read_sql_query(query, sqlite3.connect(db_path), **kw)

# ── small helpers ──────────────────────────────────────────────
def _fill_24h(df, col="cnt", default=0):
    base = pd.DataFrame({"hr": range(24)})
    return base.merge(df, on="hr", how="left").fillna({col: default})

def _split_agent(ua: str):
    ua = (ua or "").lower()
    # platform
    if   "android" in ua: plat = "Android"
    elif any(k in ua for k in ["iphone","ipad","ios"]): plat = "iOS"
    elif "windows" in ua: plat = "Windows"
    elif "mac os x" in ua: plat = "macOS"
    elif "linux"   in ua: plat = "Linux"
    else:                    plat = "Other"
    # browser
    if   "edge" in ua:                    br = "Edge"
    elif "chrome"  in ua and "chromium" not in ua: br = "Chrome"
    elif "safari"  in ua and "chrome"   not in ua: br = "Safari"
    elif "firefox" in ua:                br = "Firefox"
    elif any(k in ua for k in ["curl","wget"]):     br = "CLI"
    else: br = "Other"
    return plat, br

def _save_plot(fname):
    plt.tight_layout()
    plt.savefig(STATIC_DIR / fname, dpi=120, bbox_inches="tight")
    plt.close()

# ───────────────────────────────────────────────────────────────
#  PLOT FUNCTIONS  (only updated ones shown in full;
#  untouched ones remain the same as before)
# ─────────────────────────────────────────────────────────────── 

def plt_avg_size_trend_latest_day(db,
                                  *,
                                  save=True,
                                  prefix="avg_size_day",
                                  static_subdir=""):
    """
    Plot average response‑payload size (bytes) per hour
    for the latest event‑day in `logs.time`.
    File is named   <prefix>_<YYYY‑MM‑DD>.png
    """
    # ── 1. find the latest event day ───────────────────────────
    latest_day_row = _run_sql(db, "SELECT DATE(MAX(time)) AS d FROM logs")
    if latest_day_row.empty or latest_day_row.iloc[0,0] is None:
        print("logs table empty."); return
    day = latest_day_row.iloc[0,0]            # e.g. '2025-07-03'

    # ── 2. average size per hour for that day ─────────────────
    df = _run_sql(db, f"""
        SELECT
            CAST(strftime('%H', time) AS INT) AS hr,
            AVG(CAST(size AS REAL))           AS sz
        FROM   logs
        WHERE  DATE(time) = '{day}'
          AND  size IS NOT NULL
        GROUP  BY hr
    """)
    if df.empty:
        print(f"No size data for {day}."); return

    df = _fill_24h(df, col="sz").sort_values("hr")
    df["label"] = (
        df["hr"].astype(str).str.zfill(2) + "-" +
        ((df["hr"] + 1) % 24).astype(str).str.zfill(2)
    )

    # ── 3. plot ───────────────────────────────────────────────
    plt.figure(figsize=(14, 6))
    ax = sns.lineplot(data=df, x="label", y="sz",
                      marker="o", linewidth=2)

    if df["sz"].notna().any():
        for idx, color in [(df["sz"].idxmax(), "red"),
                           (df["sz"].idxmin(), "green")]:
            ax.scatter(df.loc[idx, "label"], df.loc[idx, "sz"],
                       color=color, s=120, zorder=5)

    ax.set(
        title=f"Average Payload Size by Hour  ({day})\n"
              "(Red =\u00A0Max, Green =\u00A0Min)",
        xlabel="Hour window",
        ylabel="Bytes"
    )
    plt.xticks(rotation=45, ha="right")

    # ── 4. save ───────────────────────────────────────────────
    if save:
        fname = f"{prefix}_{day}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


# ------------------------------------------------------------------
#  HTTP‑status donut • latest day only
# ------------------------------------------------------------------
def plt_status_pie_latest_day(db):
    """Plot status code distribution (latest day only) as a donut chart with legend."""
    # Step 1: Get latest day
    day_row = _run_sql(db, "SELECT DATE(MAX(time)) AS d FROM logs")
    if day_row.empty or day_row.iloc[0, 0] is None:
        print("logs table empty."); return
    day = day_row.iloc[0, 0]

    # Step 2: Query status code classes for latest day
    df = _run_sql(db, f"""
        SELECT CASE
            WHEN status BETWEEN 200 AND 299 THEN '2xx Success'
            WHEN status BETWEEN 300 AND 399 THEN '3xx Redirect'
            WHEN status BETWEEN 400 AND 499 THEN '4xx Client Error'
            WHEN status BETWEEN 500 AND 599 THEN '5xx Server Error'
            ELSE 'Other' END AS status_class,
            COUNT(*) cnt
        FROM logs
        WHERE DATE(time) = '{day}'
        GROUP BY status_class
    """)
    if df.empty:
        print(f"No status data for {day}."); return

    # Step 3: Plot donut chart
    plt.figure(figsize=(10, 10))
    colors = sns.color_palette('viridis', len(df))
    total = df["cnt"].sum()

    wedges, _ = plt.pie(
        df["cnt"],
        startangle=90,
        colors=colors,
        wedgeprops=dict(width=0.4, edgecolor='w'),
        labels=None  # <-- hide labels in pie
    )

    # Step 4: Legend with full details
    legend_labels = [
        f"{row.status_class} – {row.cnt/total*100:0.1f}% ({row.cnt:,})"
        for row in df.itertuples()
    ]
    plt.legend(wedges, legend_labels,
               title="Status Class",
               loc="center left",
               bbox_to_anchor=(1.0, 0.5),
               frameon=True)

    plt.title(f"HTTP Status Code Distribution – {day}", weight="bold", pad=20)

    # Step 5: Save
    fname = f"status_pie_{day}.png"
    _save_plot(fname)
    print(f"✔ Saved → static/{fname}")

    plt.show()

# -----------------------------------------------------------------
#  Pie / donut of ALL platforms on the latest day  – keeps “Other”
# -----------------------------------------------------------------
def plt_platform_pie_latest_day(db_path: str,
                                *,
                                save: bool = True,
                                prefix: str = "platform_pie_day",
                                static_subdir: str = ""):
    """
    Pie chart of platform share for the most‑recent calendar day
    in `logs.time`, using _split_agent() to classify UA strings.

    • “Other” is kept as its own slice when present.
    • Legend shows  <Platform – x.x % (hits)>  with colours matching slices.
    • Saved to  static/<static_subdir>/<prefix>_<YYYY‑MM‑DD>_<UTCts>.png
    """
    # 1️⃣  detect latest day in logs
    day_row = _run_sql(db_path,
        "SELECT DATE(MAX(time)) AS d FROM logs")
    if day_row.empty or day_row.iloc[0, 0] is None:
        print("logs table empty."); return
    day = day_row.iloc[0, 0]                          # e.g. '2025-07-03'

    # 2️⃣  pull user‑agents for that day (cap rows if huge)
    df_raw = _run_sql(db_path, f"""
        SELECT agent
        FROM   logs
        WHERE  DATE(time) = '{day}'
        LIMIT  100000
    """)
    if df_raw.empty:
        print(f"No rows for {day}."); return

    # 3️⃣  classify → platform column
    df_raw["plat"] = df_raw["agent"].apply(
        lambda ua: _split_agent(ua)[0]
    )

    # 4️⃣  counts for each platform  (includes “Other” naturally)
    plat_df = (df_raw["plat"]
                 .value_counts()
                 .reset_index()
                 .rename(columns={"index": "Platform", "plat": "Hits"}))

    total = plat_df["Hits"].sum()

    # 5️⃣  legend labels
    legend_labels = [
    f"{row.Index} – {row.Hits/total*100:.1f}% ({row.Hits:,})"
    for row in plat_df.itertuples()
    ]

    colours = sns.color_palette("viridis", len(plat_df))

    # 6️⃣  draw donut‑pie
    plt.figure(figsize=(9, 9))
    wedges, _ = plt.pie(
        plat_df["Hits"],
        startangle=90,
        colors=colours,
        wedgeprops=dict(width=0.4, edgecolor="w"),   # donut style
        labels=None                                  # keep slices label‑free
    )

    plt.title(f"Platform Distribution – {day}",
              weight="bold", pad=20)

    #  Legend – same colours as wedges
    plt.legend(
        wedges,
        legend_labels,
        title="Platforms",
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=True,
    )

    # 7️⃣  save (UTC timestamp => cache‑safe)
    if save:
        ts    = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{day}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


def plt_top_urls_latest_day(db_path: str,
                            *,
                            top: int = 10,
                            save: bool = True,
                            prefix: str = "top_urls_day",
                            static_subdir: str = ""):
    """
    Horizontal bar‑chart of the TOP‑N most‑requested URLs
    **for the most‑recent day in `logs`**.

    • Value labels = hit count
    • Saved to  static/<static_subdir>/<prefix>_<YYYY‑MM‑DD>_<UTCts>.png
    """
    # 1️⃣  figure out the latest day we have data for
    latest_row = _run_sql(db_path,
                          "SELECT DATE(MAX(time)) AS d FROM logs")
    if latest_row.empty or latest_row.iloc[0, 0] is None:
        print("logs table empty."); return
    day = latest_row.iloc[0, 0]           # e.g. '2025‑07‑03'

    # 2️⃣  query top‑N URLs for that day
    df = _run_sql(db_path, f"""
        SELECT url,
               COUNT(*) AS hits
        FROM   logs
        WHERE  DATE(time) = '{day}'
        GROUP  BY url
        ORDER  BY hits DESC
        LIMIT  {top}
    """)
    if df.empty:
        print(f"No rows for {day}."); return

    # 3️⃣  plot
    plt.figure(figsize=(12, 0.6*len(df)+3))
    ax = sns.barplot(data=df, y="url", x="hits",
                 hue="url", dodge=False, legend=False,
                 edgecolor="black", linewidth=.5,
                 palette=sns.color_palette("viridis", len(df)))


    # value annotations
    for p in ax.patches:
        w = p.get_width()
        ax.text(w + df["hits"].max()*0.01,
                p.get_y() + p.get_height()/2,
                f"{int(w):,}",
                va="center", ha="left")

    ax.set(
        title=f"Most Accessed URLs – {day} (Top {top})",
        xlabel="Hits (requests)",
        ylabel=""
    )
    plt.tight_layout()

    # 4️⃣  save
    if save:
        ts    = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{day}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


# ------------------------------------------------------------------
#  Country‑level bar‑chart – ALL countries for the latest day
# ------------------------------------------------------------------
def plt_country_req_latest_day(db, *,
                               save=True,
                               prefix="country_requests_day",
                               static_subdir=""):
    """
    Plot hits per *country* for the most‑recent calendar day appearing
    in logs.time.  ALL countries are shown (no LIMIT).

    Saved file:  static/<static_subdir>/<prefix>_<YYYY‑MM‑DD>.png
    """
    # ── 1.  latest day in the table ────────────────────────────
    latest_day = _run_sql(db,
        "SELECT DATE(MAX(time)) AS d FROM logs").iloc[0, 0]
    if latest_day is None:
        print("logs table empty."); return

    # ── 2.  counts per country ─────────────────────────────────
    df = _run_sql(db, f"""
        SELECT country, COUNT(*) AS cnt
        FROM   logs
        WHERE  DATE(time) = '{latest_day}'
        GROUP  BY country
        ORDER  BY cnt DESC
    """)
    if df.empty:
        print(f"No rows for {latest_day}."); return

    # ── 3.  plot ───────────────────────────────────────────────
    plt.figure(figsize=(12, 0.6*len(df) + 3))
    ax = sns.barplot(data=df, y="country", x="cnt",
                     edgecolor='black', linewidth=.5)

    for p in ax.patches:
        w = p.get_width()
        ax.text(w + df["cnt"].max()*0.01,
                p.get_y() + p.get_height()/2,
                f"{int(w):,}",
                va="center", ha="left")

    ax.set(title=f"Hits by Country – {latest_day} (all countries)",
           xlabel="Hits",
           ylabel="")

    plt.tight_layout()

    # ── 4.  save (optional) ────────────────────────────────────
    if save:
        ts   = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{latest_day}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()



# ───────────────────────────────────────────────────────────────
#  Suspicious IPs by Country – last 30 days, Top‑10
# ───────────────────────────────────────────────────────────────
from datetime import datetime, timedelta

def plt_suspicious_countries_last30d(db_path: str,
                                     *,
                                     days: int = 30,
                                     top:  int = 10,
                                     save: bool = True,
                                     prefix: str = "suspicious_countries_last30d",
                                     static_subdir: str = ""):
    """
    Horizontal bar‑chart of **unique** suspicious IPs per country
    for the last `days` (default = 30) days of data in `logs`.
    """
    # 1️⃣  rolling‑window bounds
    latest_day = _run_sql(db_path,
                          "SELECT DATE(MAX(time)) AS d FROM logs"
                         ).iloc[0, 0]
    if latest_day is None:
        print("logs table empty."); return
    start_day = (datetime.fromisoformat(latest_day)
                 - timedelta(days=days)).strftime("%Y-%m-%d")

    # 2️⃣  DISTINCT‑IP counts  (use the right column!)
    df = _run_sql(db_path, f"""
        SELECT l.country,
               COUNT(DISTINCT s.suspiciousIp) AS cnt
        FROM   ip_suspicious AS s
        JOIN   logs           AS l  ON l.ip = s.suspiciousIp
        WHERE  DATE(l.time) BETWEEN '{start_day}' AND '{latest_day}'
        GROUP  BY l.country
        ORDER  BY cnt DESC
        LIMIT  {top}
    """)
    if df.empty:
        print(f"No suspicious IP rows between {start_day} and {latest_day}."); return

    # 3️⃣  plotting (unchanged)
        # 3️⃣  plotting
    plt.figure(figsize=(12, 0.6*len(df)+3))

    # 🔧 <‑‑‑ ONLY THIS LINE CHANGED
    ax = sns.barplot(
        data=df,
        y="country", x="cnt",
        hue="country",            # tell Seaborn *which* variable gets the colours
        palette=sns.color_palette("rocket", len(df)),
        legend=False,             # we don’t need a legend for country names
        edgecolor="black", linewidth=.5
    )


    for p in ax.patches:
        w = p.get_width()
        ax.text(w + df["cnt"].max()*0.01,
                p.get_y() + p.get_height()/2,
                f"{int(w):,}",
                va="center", ha="left")

    ax.set(title=f"Suspicious IPs by Country – last {days} days (Top {top})",
           xlabel="Unique suspicious IPs",
           ylabel="")
    plt.tight_layout()

    # 4️⃣  save
    if save:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{latest_day}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


# ------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------
def _latest_day_with_categories(db_path: str) -> str | None:
    """
    Return the most‑recent DATE(time) that actually has matching rows
    in ip_eachHour_category. Returns None if none found.
    """
    sql = """
    SELECT MAX(day) AS d FROM (
        SELECT DATE(l.time) AS day
        FROM   logs l
        JOIN   ip_eachHour_category ic
               ON ic.ip = l.ip
              AND (
                   CAST(strftime('%H', l.time) AS INT) || '-' ||
                   CAST((CAST(strftime('%H', l.time) AS INT)+1)%24 AS INT)
                  ) = ic.hour
    );
    """
    df = _run_sql(db_path, sql)
    return df.iloc[0, 0] if not df.empty else None

def _join_logs_to_categories(db_path: str, day: str):
    """
    Return a DataFrame [hour, category] for one calendar day.
    """
    return _run_sql(db_path, f"""
        SELECT ic.hour, ic.category
        FROM   ip_eachHour_category ic
        JOIN   logs l
               ON l.ip = ic.ip
              AND (
                   CAST(strftime('%H', l.time) AS INT) || '-' ||
                   CAST((CAST(strftime('%H', l.time) AS INT)+1)%24 AS INT)
                  ) = ic.hour
        WHERE  DATE(l.time) = '{day}'
    """)

# ------------------------------------------------------------------
#  Core plotting routine
# ------------------------------------------------------------------
def save_category_breakdown_one(db_path: str,
                                day: str,
                                bucket: str = 'All',
                                prefix: str = "category_breakdown",
                                static_subdir: str = ""):
    """
    Save ONE bar‑chart for (day, bucket) into static/.
    bucket = 'All' or e.g. '13-14'
    """
    df = _join_logs_to_categories(db_path, day)
    if bucket != 'All':
        df = df[df['hour'] == bucket]
    if df.empty:
        print(f"[skip] {day} bucket={bucket} has no rows."); return

    plot_df = (df.groupby('category').size()
                 .reset_index(name='cnt')
                 .sort_values('cnt', ascending=False))

    plt.figure(figsize=(12, 6))
    sns.barplot(data=plot_df, x='category', y='cnt',
                edgecolor='black', linewidth=0.5)
    for p in plt.gca().patches:
        h = p.get_height()
        plt.text(p.get_x()+p.get_width()/2.,
                 h + plot_df['cnt'].max()*0.01,
                 f'{int(h):,}', ha='center', va='bottom')

    slice_txt = f"{day} • All hours" if bucket == 'All' else f"{day} • Hour {bucket}"
    plt.title(f"Traffic Categories • {slice_txt}", weight='bold', pad=20)
    plt.ylabel("Count"); plt.xlabel("Category")
    plt.xticks(rotation=45, ha='right')

    label = bucket.replace('-', '_') if bucket != 'All' else 'all'
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    fname = f"{prefix}_{day}_{label}_{ts}.png"
    if static_subdir:
        fname = f"{static_subdir.rstrip('/')}/{fname}"
    _save_plot(fname)
    print(f"✔ Saved → static/{fname}")

# ------------------------------------------------------------------
#  Batch exporter: latest day, all buckets
# ------------------------------------------------------------------
def export_category_breakdown_latest_day_all_hours(db_path: str,
                                                   prefix="category_breakdown",
                                                   static_subdir=""):
    """
    Detect the latest calendar day in logs.time that also appears in
    ip_eachHour_category, then save:
      • one 'All hours' plot
      • one plot per hour bucket that exists that day.
    Put THIS function in PLOTS_TO_RUN.
    """
    latest_day = _latest_day_with_categories(db_path)
    if latest_day is None:
        print("❌  No day with category data found."); return

    df_day = _join_logs_to_categories(db_path, latest_day)
    buckets = sorted(df_day['hour'].unique(), key=lambda s: int(s.split('-')[0]))

    print(f"📆 Exporting category plots for {latest_day} …")
    save_category_breakdown_one(db_path, latest_day, 'All',
                                prefix=prefix, static_subdir=static_subdir)
    for b in buckets:
        save_category_breakdown_one(db_path, latest_day, b,
                                    prefix=prefix, static_subdir=static_subdir)
    print("✅  All category plots done.")



def plt_detection_counts_last7d(db_path: str,
                                *,
                                days:   int  = 7,
                                top:    int  = 15,
                                save:   bool = True,
                                prefix: str  = "top_suspects_last7d",
                                static_subdir: str = ""):
    """
    Bar‑chart of IPs with the **most suspicion events** in the last `days`
    (default = 7). One event = one row in `ip_suspicious` within that window.
    """

    # 1️⃣ Date window
    end_day   = datetime.utcnow().date()
    start_day = end_day - timedelta(days=days - 1)
    sd, ed    = start_day.isoformat(), end_day.isoformat()

    # 2️⃣ Query suspicion events per IP using correct time column
    df = _run_sql(db_path, f"""
        SELECT suspiciousIp   AS ip,
               COUNT(*)       AS events
        FROM   ip_suspicious
        WHERE  DATE(time) BETWEEN '{sd}' AND '{ed}'
        GROUP  BY ip
        ORDER  BY events DESC
        LIMIT  {top}
    """)
    if df.empty:
        print(f"No suspicion events between {sd} and {ed}."); return

    # 3️⃣ Plotting
    plt.figure(figsize=(12, 0.6*len(df)+3))
    ax = sns.barplot(data=df, y="ip", x="events",
                 hue="ip", dodge=False,
                 edgecolor="black", linewidth=0.5,
                 palette=sns.color_palette("rocket", len(df)))


    for p, val in zip(ax.patches, df["events"]):
        ax.text(p.get_width() + df["events"].max()*0.01,
                p.get_y() + p.get_height()/2,
                f"{val:,}",
                va="center", ha="left")

    ax.set(
        title=f"Most Flagged IPs • last {days} days ({sd} → {ed})",
        xlabel="Detection Count",
        ylabel="IP Address"
    )
    plt.tight_layout()

    # 4️⃣ Save
    if save:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{ed}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


def plt_heatmap(db):
    """Plot heatmap of requests by weekday and hour."""
    df = _run_sql(db, """
        SELECT strftime('%w', time) wd, strftime('%H', time) hr, COUNT(*) cnt 
        FROM logs 
        GROUP BY wd, hr""")
    if df.empty: return
    
    # Convert to proper types and pivot
    df["wd"] = df["wd"].astype(int)
    df["hr"] = df["hr"].astype(int)
    pivot = df.pivot(index="wd", columns="hr", values="cnt").fillna(0)
    
    # Create custom labels for weekdays
    weekday_labels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    
    plt.figure(figsize=(16, 8))
    sns.heatmap(pivot, cmap="YlOrRd", linewidths=0.5, 
                xticklabels=range(24), yticklabels=weekday_labels)
    
    plt.title("Request Heatmap: Hourly Activity by Weekday", weight="bold", pad=20)
    plt.ylabel("Weekday")
    plt.xlabel("Hour of Day")
    _save_plot("heatmap_hits.png")

def plt_browser_top10_latest_day(db, *,
                                 N: int = 10,
                                 save=True,
                                 prefix="browser_requests_top10_day",
                                 static_subdir=""):
    """
    Top‑N browsers (plus 'Other') for the MOST‑RECENT day
    found in logs.time.  Saves to:
        static/<static_subdir>/<prefix>_<YYYY‑MM‑DD>.png
    """
    # ── 1. detect latest event day ─────────────────────────────
    latest_day_row = _run_sql(db,
        "SELECT DATE(MAX(time)) AS d FROM logs")
    if latest_day_row.empty or latest_day_row.iloc[0,0] is None:
        print("logs table empty."); return
    day = latest_day_row.iloc[0,0]           # e.g. '2025-07-03'

    # ── 2. pull user‑agents for that day ───────────────────────
    df_raw = _run_sql(db, f"""
        SELECT agent FROM logs
        WHERE  DATE(time) = '{day}'
    """)
    if df_raw.empty:
        print(f"No rows for {day}."); return

    df_raw["browser"] = df_raw["agent"].apply(_extract_browser_generic)

    # ── 3. top‑N logic (same as before) ────────────────────────
    counts = df_raw["browser"].value_counts()
    other_cnt       = counts.get("Other", 0)
    counts_no_other = counts.drop(labels="Other", errors="ignore")
    topN            = counts_no_other.head(N)

    df_plot = (topN.reset_index(name="cnt")
                    .rename(columns={"index":"browser"})
                    .sort_values("cnt", ascending=False)
                    .reset_index(drop=True))
    df_plot = pd.concat(
        [df_plot, pd.DataFrame([{"browser":"Other","cnt":other_cnt}])],
        ignore_index=True
    )
    bar_order = df_plot["browser"].tolist()

    # ── 4. plot ────────────────────────────────────────────────
    plt.figure(figsize=(12, max(6, .6*len(df_plot))))
    sns.barplot(data=df_plot, y="browser", x="cnt",
                order=bar_order, edgecolor="black",
                linewidth=.5, color=sns.color_palette("viridis",1)[0])

    for p in plt.gca().patches:
        w = p.get_width()
        plt.text(w + df_plot["cnt"].max()*0.02,
                 p.get_y()+p.get_height()/2,
                 f"{int(w):,}", va="center", ha="left")

    plt.title(f"Top {N} Browsers Hits ({day})", weight="bold", pad=15)
    plt.xlabel("Hits"); plt.ylabel("")

    # ── 5. save ────────────────────────────────────────────────
    if save:
        fname = f"{prefix}_{day}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()

# -----------------------------------------------------------------
#  Pie / donut of ALL platforms on the latest day  – keeps “Other”
# -----------------------------------------------------------------
def plt_platform_pie_latest_day(db_path: str,
                                *,
                                save: bool = True,
                                prefix: str = "platform_pie_day",
                                static_subdir: str = ""):
    """
    Pie chart of platform share for the most‑recent calendar day
    in `logs.time`, using _split_agent() to classify UA strings.

    • “Other” is kept as its own slice when present.
    • Legend shows  <Platform – x.x % (hits)>  with colours matching slices.
    • Saved to  static/<static_subdir>/<prefix>_<YYYY‑MM‑DD>_<UTCts>.png
    """
    # 1️⃣  detect latest day in logs
    day_row = _run_sql(db_path,
        "SELECT DATE(MAX(time)) AS d FROM logs")
    if day_row.empty or day_row.iloc[0, 0] is None:
        print("logs table empty."); return
    day = day_row.iloc[0, 0]                          # e.g. '2025-07-03'

    # 2️⃣  pull user‑agents for that day (cap rows if huge)
    df_raw = _run_sql(db_path, f"""
        SELECT agent
        FROM   logs
        WHERE  DATE(time) = '{day}'
        LIMIT  100000
    """)
    if df_raw.empty:
        print(f"No rows for {day}."); return

    # 3️⃣  classify → platform column
    df_raw["plat"] = df_raw["agent"].apply(
        lambda ua: _split_agent(ua)[0]
    )

    # 4️⃣  counts for each platform  (includes “Other” naturally)
    plat_df = (
        df_raw["plat"]
        .value_counts()
        .rename_axis("Platform")  # sets index name
        .reset_index(name="Hits") # converts to column + renames count column
    )


    total = plat_df["Hits"].sum()

    # ✅ 5️⃣ FIX: generate legend labels without `row.Platform`
    legend_labels = [
        f"{row['Platform']} – {row['Hits']/total*100:.1f}% ({row['Hits']:,})"
        for _, row in plat_df.iterrows()
    ]

    colours = sns.color_palette("viridis", len(plat_df))

    # 6️⃣  draw donut‑pie
    plt.figure(figsize=(9, 9))
    wedges, _ = plt.pie(
        plat_df["Hits"],
        startangle=90,
        colors=colours,
        wedgeprops=dict(width=0.4, edgecolor="w"),   # donut style
        labels=None                                  # keep slices label‑free
    )

    plt.title(f"Platform Distribution – {day}",
              weight="bold", pad=20)

    #  Legend – same colours as wedges
    plt.legend(
        wedges,
        legend_labels,
        title="Platforms",
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=True,
    )

    # 7️⃣  save (UTC timestamp => cache‑safe)
    if save:
        ts    = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{day}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


def plt_size_vs_status_latest_day(db,
                                  *,
                                  save=True,
                                  prefix="size_vs_status_day",
                                  static_subdir=""):
    """
    Scatter‑plot of response size vs. status code
    for the latest calendar day present in logs.time.
    Each dot = one request (alpha=.6 to reveal density).

    Output file:
        static/<static_subdir>/<prefix>_<YYYY‑MM‑DD>.png
    """
    # ── 1. find the latest event day ───────────────────────────
    latest_row = _run_sql(db, "SELECT DATE(MAX(time)) AS d FROM logs")
    if latest_row.empty or latest_row.iloc[0, 0] is None:
        print("logs table empty."); return
    day = latest_row.iloc[0, 0]                       # e.g. '2025‑07‑03'

    # ── 2. pull rows for that day ─────────────────────────────
    df = _run_sql(db, f"""
        SELECT status,
               CAST(size AS REAL) AS size
        FROM   logs
        WHERE  DATE(time) = '{day}'
          AND  size IS NOT NULL
    """)
    if df.empty:
        print(f"No size data for {day}."); return

    # ── 3. plot ───────────────────────────────────────────────
    plt.figure(figsize=(14, 8))
    sns.scatterplot(data=df,
                    x="status", y="size",
                    alpha=.6, s=50,
                    hue="status", palette="viridis",
                    legend=False)

    plt.title(f"Response Size vs. Status Code  – {day}",
              weight="bold", pad=18)
    plt.xlabel("HTTP Status Code")
    plt.ylabel("Response Size (bytes)")
    plt.tight_layout()

    # ── 4. save ───────────────────────────────────────────────
    if save:
        fname = f"{prefix}_{day}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()

    
def plt_request_methods(db):
    """Plot distribution of HTTP request methods."""
    df = _run_sql(db, """
        SELECT method, COUNT(*) as count 
        FROM logs 
        GROUP BY method 
        ORDER BY count DESC""")
    if df.empty: return
    
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df, x="method", y="count", edgecolor='black', linewidth=0.5)
    
    # Add value annotations
    for p in ax.patches:
        height = p.get_height()
        ax.text(p.get_x() + p.get_width()/2., height + max(df["count"])*0.01,
                f'{int(height):,}', ha='center', va='bottom')
    
    plt.title("HTTP Request Methods Distribution", weight="bold", pad=20)
    plt.xlabel("Method")
    plt.ylabel("Count")
    _save_plot("request_methods.png")
    
def plt_suspicious_reasons(db):
    """Plot reasons for IPs being marked as suspicious in the last 7 days."""

    # 1️⃣ Get date window from logs table
    res = _run_sql(db, "SELECT MIN(DATE(time)) AS min_day, MAX(DATE(time)) AS max_day FROM logs")
    max_day = res.iloc[0]["max_day"]
    min_day = (datetime.fromisoformat(max_day) - timedelta(days=6)).strftime("%Y-%m-%d")
    
    # 2️⃣ Fetch reason counts for suspicious IPs linked to logs within the last 7 days
    df = _run_sql(db, f"""
        SELECT s.reason,
               COUNT(*) AS count
        FROM   ip_suspicious AS s
        JOIN   logs          AS l ON l.ip = s.suspiciousIp
        WHERE  DATE(l.time) BETWEEN '{min_day}' AND '{max_day}'
        GROUP  BY s.reason
        ORDER  BY count DESC
    """)
    if df.empty:
        print(f"No suspicious IP activity between {min_day} and {max_day}.")
        return

    # 3️⃣ Plotting
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df, y="reason", x="count", edgecolor='black', linewidth=0.5)
    
    for p in ax.patches:
        width = p.get_width()
        plt.text(width + max(df["count"]) * 0.01,
                 p.get_y() + p.get_height() / 2,
                 f'{int(width):,}', ha='left', va='center')
    
    plt.title(f"Reasons for Suspicious IPs – {min_day} to {max_day}", weight="bold", pad=20)
    plt.xlabel("Count(non-unique ips considered)")
    plt.ylabel("Reason")
    plt.tight_layout()

    # 4️⃣ Save
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    fname = f"suspicious_reasons_{min_day}_to_{max_day}_{ts}.png"
    _save_plot(fname)
    print(f"✔ Saved → static/{fname}")

    plt.show()


def plt_suspects_last15_days_bars(db,
                                  *,
                                  save=True,
                                  prefix="suspects_last15d_bars",
                                  static_subdir=""):
    """
    Bar chart: # of suspicious IPs per calendar day (last 15 days).

    • Missing days are shown as 0.
    • Each bar has its value printed on top.
    • Pastel colour palette for a fresh look.
    """
    # ── 1. pull counts from DB ─────────────────────────────────
    df = _run_sql(db, """
        SELECT DATE(time) AS day, COUNT(*) AS cnt
        FROM   ip_suspicious
        WHERE  DATE(time) >= DATE('now', '-14 day')
        GROUP  BY day
        ORDER  BY day
    """)
    if df.empty:
        print("No suspicious‑IP data in the last 15 days."); return

    # ── 2. ensure every day is present ─────────────────────────
    all_days = pd.date_range(end=pd.Timestamp.today().normalize(),
                             periods=15, freq="D")
    df = (df.set_index("day")
            .reindex(all_days.strftime("%Y-%m-%d"), fill_value=0)
            .rename_axis("day")
            .reset_index())

    # ── 3. plot ────────────────────────────────────────────────
    plt.figure(figsize=(12, 6))
    palette = sns.color_palette("pastel", len(df))
    ax = sns.barplot(
        data=df,
        x="day", y="cnt",
        hue="day",       
        palette=palette,
        legend=False,      
        edgecolor="black", linewidth=.5
    )


    # value labels
    for p, val in zip(ax.patches, df["cnt"]):
        ax.text(p.get_x() + p.get_width()/2,
                p.get_height() + max(df["cnt"])*0.02,
                f"{val:,}",
                ha="center", va="bottom", fontsize=10)

    ax.set(
        title="Suspicious IPs per Day – Last 15 Days",
        xlabel="Date",
        ylabel="Count"
    )
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    # ── 4. save ────────────────────────────────────────────────
    if save:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()

        


def plt_blocked_ips_latest_day(db, *,
                               save=True,
                               prefix="blocked_ips_day",
                               static_subdir=""):
    """
    Latest‑day blocked IPs bar‑chart.
      • colour per‑row by client_block_status
      • label  = client_blocked_at (HH:MM:SS, 24‑h)
      • legend colours match bars
    """
    # 1️⃣  latest calendar day present
    day = _run_sql(db,
        "SELECT DATE(MAX(backend_blocked_at)) AS d FROM blocked_log"
    ).iloc[0, 0]
    if day is None:
        print("blocked_log empty"); return

    # 2️⃣  rows for that day
    df = _run_sql(db, f"""
        SELECT ip,
               detection_count,
               COALESCE(TRIM(LOWER(client_block_status)),'‑') AS status,
               TIME(client_blocked_at)                       AS client_time
        FROM   blocked_log
        WHERE  DATE(backend_blocked_at) = '{day}'
        ORDER  BY detection_count DESC, ip
    """)
    if df.empty:
        print(f"No blocked IPs on {day}."); return

    # 3️⃣  status → colour look‑up
    colour_lut = {
        'success': '#4caf50',   # green
        'ok'     : '#4caf50',
        'failed' : '#e53935',   # red
        'error'  : '#e53935',
        '‑'      : '#9e9e9e',   # unknown / blank
    }
    bar_colours = df['status'].map(lambda s: colour_lut.get(s, '#9e9e9e'))

    # 4️⃣  plot (no hue; paint each patch afterwards)
    plt.figure(figsize=(12, max(6, .6*len(df))))
    ax = sns.barplot(
        data=df,
        y='ip', x='detection_count',
        order=df['ip'],            # keep our order
        edgecolor='black', linewidth=.5,
        color='#ffffff'            # temp colour – will be overwritten
    )

    # paint each bar, then annotate its time
    for bar, colour, t in zip(ax.patches, bar_colours, df['client_time']):
        bar.set_facecolor(colour)
        ax.text(bar.get_width() + df['detection_count'].max()*0.02,
                bar.get_y() + bar.get_height()/2,
                t or '–', va='center', ha='left')

    # 5️⃣  legend – build only for statuses that actually occur
    handles, labels = [], []
    for st in df['status'].unique():
        handles.append(plt.Rectangle((0,0),1,1, fc=colour_lut.get(st,'#9e9e9e'),
                                     ec='black', linewidth=.5))
        labels.append(st)
    ax.legend(handles, labels, title='Client block status',
              loc='lower right', frameon=True)

    ax.set(title=f"Blocked IPs on {day}",
           xlabel="Detection count", ylabel="")
    plt.tight_layout()

    # 6️⃣  save (timestamp → bypass caching)
    if save:
        ts    = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        fname = f"{prefix}_{day}_{ts}.png"
        if static_subdir:
            fname = f"{static_subdir.rstrip('/')}/{fname}"
        _save_plot(fname)
        print(f"✔ Saved → static/{fname}")

    plt.show()


# ── Generic UA → browser extractor (no hard‑coding) ────────────
_skip_tokens = set("""
mozilla compatible version windows linux applewebkit khtml trident
like mobile safari gecko
""".split())

_token_re = re.compile(r'([a-z0-9\+\-\.]+)\/[\d\.]+', re.I)

def _extract_browser_generic(ua: str) -> str:
    """
    Return the first non‑generic product token from a UA string.
    Falls back to 'Other' when nothing useful is found.
    """
    if not ua:
        return "Other"

    ua_low = ua.lower()

    # Look for tokens like Name/1.2.3
    for tok in _token_re.findall(ua_low):
        if tok not in _skip_tokens and len(tok) > 2:
            return tok.capitalize()

    # Fallback: any word ≥3 chars not in skip list
    words = re.findall(r'[a-z][a-z0-9\+\-]{2,}', ua_low)
    for w in words:
        if w not in _skip_tokens:
            return w.capitalize()

    return "Other"


# ── all other plotting functions stay unchanged ────────────────
# (keep them from your previous cell)

# ----------------------------------------------------------------
#  RUN EVERYTHING
# ----------------------------------------------------------------
DB_PATH = "access_logs.db"   # adjust if needed

PLOTS_TO_RUN = [
    plt_suspects_last15_days_bars,
    plt_platform_pie_latest_day,
    plt_status_pie_latest_day,
    plt_top_urls_latest_day,
    plt_country_req_latest_day,
    plt_suspicious_countries_last30d,
    export_category_breakdown_latest_day_all_hours,
    plt_avg_size_trend_latest_day,
    plt_detection_counts_last7d,
    plt_heatmap,
    plt_browser_top10_latest_day,
    plt_size_vs_status_latest_day,
    plt_blocked_ips_latest_day,
    plt_request_methods,
    plt_suspicious_reasons,
]

for fn in PLOTS_TO_RUN:
    try:
        print(f"Running → {fn.__name__}", end=" … ")
        fn(DB_PATH)
        print("done ✓")
    except Exception as e:
        print(f"FAILED ✗  ({e})")



# In[2]:


# ───────────────────────────────────────────────────────────────
#  Updated refresh_and_detect with enhanced visualizations
# ───────────────────────────────────────────────────────────────
def refresh_and_detect():
    """
    Rebuild derived tables, classify hours, run detections,
    enrich Unknown countries, then generate all visualisations.
    Includes enhanced plots with better annotations and styling.
    """
    # 1️⃣ Country enrichment
    GeoCountryUpdater(Config.DB_PATH, "./resources/geoliteCountry/GeoLite2-Country.mmdb").run()

    # 2️⃣ Feature builders & classifiers
    builder = AdvancedLogFeatureBuilder(Config.DB_PATH)
    analyzer = HourlyHitAnalyzer(Config.DB_PATH)
    classifier = EachHourCategoryClassifier(Config.DB_PATH)

    builder.run()
    analyzer.run_analysis()
    classifier.run()

    # 3️⃣ Generate/refresh all plots with enhanced versions
    plot_functions = [
        plt_suspects_last15_days_bars,
        plt_platform_pie_latest_day,
        plt_status_pie_latest_day,
        plt_top_urls_latest_day,
        plt_country_req_latest_day,
        plt_suspicious_countries_last30d,
        export_category_breakdown_latest_day_all_hours,
        plt_avg_size_trend_latest_day,
        plt_detection_counts_last7d,
        plt_heatmap,
        plt_browser_top10_latest_day,
        plt_size_vs_status_latest_day,
        plt_blocked_ips_latest_day,
        plt_request_methods,
        plt_suspicious_reasons,
    ]

    print("Generating visualizations...")
    for i, plot_fn in enumerate(plot_functions, 1):
        try:
            print(f"  [{i}/{len(plot_functions)}] {plot_fn.__name__}", end="... ")
            plot_fn(Config.DB_PATH)
            print("✓")
        except Exception as e:
            print(f"✗ Failed: {str(e)}")
    
    print("\nVisualization refresh complete.")
    print(f"Plots saved to: {STATIC_DIR.absolute()}")




# In[2]:


# #clearing static folder
# import shutil, os

# def clean_static_dir(keep_exts=(".css", ".js", ".html", ".ico")):
#     """
#     Delete everything in STATIC_DIR except files with extensions you
#     explicitly want to keep (default keeps typical web assets).
#     • keep_exts = ()    → nuke absolutely everything.
#     """
#     for item in STATIC_DIR.iterdir():
#         if item.is_file():
#             if keep_exts and item.suffix.lower() in keep_exts:
#                 continue        # skip whitelisted assets
#             item.unlink()       # delete file
#         elif item.is_dir():
#             shutil.rmtree(item) # delete sub‑folder recursively
#     print(f"✔ STATIC_DIR cleaned → {STATIC_DIR}")

# clean_static_dir(keep_exts=())    


# In[3]:


# import sqlite3

# con = sqlite3.connect("access_logs.db")
# cursor = con.cursor()
# cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
# tables = cursor.fetchall()
# con.close()
# tables


# In[41]:


# #!/usr/bin/env python3
# # print_blocked_and_count.py
# import sqlite3, pathlib

# DB_PATH = pathlib.Path("access_logs.db")   # ➊  adjust if needed

# def pretty_dump(table, conn, order_by=None):
#     """Print one SQLite table in your preferred style."""
#     cur  = conn.cursor()
#     cols = [row[1] for row in cur.execute(f"PRAGMA table_info({table});")]
#     print(f"\n📂 Table: {table}")
#     print(f"🔸 Columns: {cols}")

#     qry  = f"SELECT * FROM {table}"
#     if order_by:
#         qry += f" ORDER BY {order_by}"
#     for row in cur.execute(qry):
#         print(dict(zip(cols, row)))

# if __name__ == "__main__":
#     if not DB_PATH.exists():
#         raise SystemExit(f"❌  DB file not found: {DB_PATH}")

#     with sqlite3.connect(DB_PATH) as conn:
#         # ➋  print all rows of blocked_log
#         pretty_dump("blocked_log", conn, order_by="detected_at")

#         # ➌  count IDs in logs
#         total_ids = conn.execute("SELECT COUNT(id) FROM logs;").fetchone()[0]
#         print(f"\n🧮 Total rows in logs: {total_ids}")


# In[ ]:




