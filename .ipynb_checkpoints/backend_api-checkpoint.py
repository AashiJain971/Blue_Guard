from flask import Flask, request, jsonify
import sqlite3
import ipaddress
from datetime import datetime# 🔄 ADD
import time
# ─── local modules ───────────────────────────────────────────────
from siem5realtime import (
    AnomalyExplainerPipeline,
    Config,
    refresh_and_detect,
    simulate_realtime_stream
)
from siem5realtime import MultiIPDDoSDetector      # 🔄 ADD  (file from Section-1)
from datetime import datetime
from zoneinfo import ZoneInfo   # ← add this import at the top of the file

IST = ZoneInfo("Asia/Kolkata")  # ← one-time constant


# ─── Flask setup ────────────────────────────────────────────────
app = Flask(__name__, static_folder="static")

# Make ONE shared pipeline instance
pipeline = AnomalyExplainerPipeline(Config)

# 🔄 ADD ──────────────────────────────────────────────────────────
# Instantiate the 1-second multi-IP burst detector.
# • It writes to ddos_multiple_ip
# • Calls pipeline.handle_ddos_ips() so the swarm IPs go through
#   ip_suspicious  ➜  Slack / e-mail  ➜  block list
ddos_watcher = MultiIPDDoSDetector(
    db_path        = Config.DB_PATH,
    alert_callback = pipeline.handle_ddos_ips,
    window_s       = 1,      # analysis bucket = 1 second
    hits_thr       = 800,    # tweak to your baseline RPS
    uniq_thr       = 120,    # tweak to expected uniq-IP/s
    cooldown_s     = 60      # don’t fire twice within 1 min
)

# ─── helper: detect RFC1918 / local IPs ─────────────────────────
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ─── Route: receive client log batch ────────────────────────────
@app.route("/send_logs", methods=["POST"])
def receive_logs():
    try:
        logs = request.get_json()
        if not isinstance(logs, list):
            return jsonify({"error": "Expected list of logs"}), 400

        # ── 1️⃣ OPEN writer connection ──────────────────────────────
        conn = sqlite3.connect(Config.DB_PATH, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()

        # ensure raw-logs table exists  💠  (added ingest_ts column)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            ip        TEXT,
            time      TEXT,
            method    TEXT,
            url       TEXT,
            status    INTEGER,
            size      INTEGER,
            agent     TEXT,
            country   TEXT,
            ingest_ts TEXT          -- 💠 NEW: arrival time in SIEM
        );
        """)

        burst_events = []

               # ── 2️⃣ INSERT every log row ────────────────────────────────
        for log in logs:
            arrival_dt = datetime.now(IST)                   # true datetime in IST
            arrival_ts = arrival_dt.isoformat(timespec="microseconds")  # 'YYYY-MM-DDTHH:MM:SS+05:30'

            ip      = log.get("ip", "")
            country = "Private/Local Network" if is_private_ip(ip) else "Unknown"

            cursor.execute("""
                INSERT INTO logs (ip, time, method, url, status, size, agent,
                                  country, ingest_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                ip,
                str(log.get("time")),
                str(log.get("method")),
                str(log.get("url")),
                int(log.get("status") or 0),
                int(log.get("size") or 0),
                str(log.get("agent")),
                country,
                arrival_ts          # ← still store the string
            ))

            # keep (ip, arrival_dt) for burst analysis  🆕 pass the datetime
            burst_events.append((ip, arrival_dt))


        conn.commit()
        conn.close()

        # ── 3️⃣ Feed events to the 1-second DDoS detector ──────────
        for ip, ts in burst_events:                          # ts is arrival_ts
            ddos_watcher.ingest(ip, ts)

        # ── 4️⃣ Refresh derived tables + run rule/ML ──────────────
        refresh_and_detect()

        return jsonify({"status": "success", "received": len(logs)})

    except Exception as e:
        print("❌ Exception in /send_logs:", e)
        return jsonify({"error": str(e)}), 500

# ─── Route: expose current block list ──────────────────────────
@app.route("/get_blocklist")
def get_blocklist():
    with sqlite3.connect(Config.DB_PATH) as conn:
        ips = [r[0] for r in conn.execute(
            "SELECT ip FROM blocked_log WHERE client_blocked_at IS NULL"
        )]
    return jsonify({"blocked_ips": ips})



def add_column_if_missing(db_path: str,
                          table: str,
                          colname: str,
                          coldef: str) -> None:
    """
    Add `colname coldef` to `table` only if it isn't already present.
    Example:
        add_column_if_missing("siem.sqlite", "blocked_log",
                              "client_blocked_at", "TEXT")
    """
    with sqlite3.connect(db_path) as conn:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table});")}
        if colname not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {colname} {coldef};")
            print(f"✅ added column {colname}")
        else:
            print(f"ℹ️ column {colname} already exists – skipped")


# @app.post("/client_blocked")
# def client_blocked():
#     data   = request.get_json(force=True, silent=True) or {}
#     ip     = data.get("ip")
#     ts     = data.get("client_blocked_at")
#     status = data.get("status", "ok")          # "ok" | "failed"

#     if not ip or not ts:
#         return {"error": "ip and client_blocked_at required"}, 400

#     # single UPSERT covers both first‑insert + later updates
#     with sqlite3.connect(Config.DB_PATH) as conn:
#         conn.execute("""
#             INSERT INTO blocked_log (
#                 ip, client_blocked_at, client_block_status,
#                 detected_at, backend_blocked_at, detection_count
#             )
#             VALUES (?, ?, ?, NULL, NULL, 0)
#             ON CONFLICT(ip) DO UPDATE
#               SET client_blocked_at  = excluded.client_blocked_at,
#                   client_block_status = excluded.client_block_status;
#         """, (ip, ts, status))
#         conn.commit()

#     return {"ok": True}

@app.post("/client_blocked")
def client_blocked():
    data   = request.get_json(force=True, silent=True) or {}
    ip     = data.get("ip")
    ts     = data.get("client_blocked_at")
    status = data.get("status", "ok")  # "ok" | "failed"

    if not ip or not ts:
        return {"error": "ip and client_blocked_at required"}, 400

    with sqlite3.connect(Config.DB_PATH) as conn:
        cur = conn.cursor()

        # Insert if IP doesn't exist
        cur.execute("SELECT client_blocked_at FROM blocked_log WHERE ip = ?", (ip,))
        result = cur.fetchone()

        if not result:
            # New IP — insert all values
            cur.execute("""
                INSERT INTO blocked_log (
                    ip, client_blocked_at, client_block_status,
                    detected_at, backend_blocked_at, detection_count
                ) VALUES (?, ?, ?, NULL, NULL, 0)
            """, (ip, ts, status))
        elif result[0] is None:
            # Existing IP but client_blocked_at is NULL — update it
            cur.execute("""
                UPDATE blocked_log
                SET client_blocked_at = ?, client_block_status = ?
                WHERE ip = ?
            """, (ts, status, ip))

        conn.commit()

    return {"ok": True}


# ─── Boot Flask ───────────────────────────────────────────────
if __name__ == "__main__":
    # 1. Integrity check
    with sqlite3.connect(Config.DB_PATH) as c:
        ok = c.execute("PRAGMA integrity_check;").fetchone()[0]
        if ok != "ok":
            raise RuntimeError("SQLite file is corrupt! Restore from backup.")
        print("✅  SQLite integrity_check → ok")

    # 2️⃣ add columns (method 1 or 2)
    add_column_if_missing(Config.DB_PATH, "blocked_log",
                          "client_blocked_at",   "TEXT")
    add_column_if_missing(Config.DB_PATH, "blocked_log",
                          "client_block_status", "TEXT DEFAULT 'NULL'")

    # ignore “duplicate column” errors — already handled above

    # 3. Guarantee 1‑row‑per‑IP forever
    with sqlite3.connect(Config.DB_PATH) as c:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_blocked_log_ip ON blocked_log(ip);")
        print("✅  UNIQUE index on ip ensured")

    # 4. Kick off simulation thread & start Flask
    from threading import Thread
    t = Thread(target=simulate_realtime_stream, args=(pipeline, 1), daemon=True)
    t.start()

    print("🚀  Starting Flask server...")
    app.run(host="0.0.0.0", port=5050, debug=True, use_reloader=False)
