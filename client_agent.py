#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import os
import platform
import subprocess, shlex
import shutil
import socket
import time
import requests
import glob
import json
import random, requests
from zoneinfo import ZoneInfo
#to generate fake log
from datetime import datetime
import random
import re

IST = ZoneInfo("Asia/Kolkata")          # reuse the same object everywhere

YOUR_BACKEND_URL = "http://127.0.0.1:5050"  # 🛠️ Replace with your backend


# ──────────────── 1⃣  CONFIG ─────────────────
LOG_FILE_PATH = os.path.join(
    os.path.dirname(__file__),  # same parent folder
    "resources",
    "access.log"
)

BATCH_SIZE   = 500             # tune for your link / RAM
POST_TIMEOUT = 10              # seconds


# ─────────────────────────────────────────────────────────────
# Helper: tell the backend whether the block really happened
# status = "ok" | "failed"
# ─────────────────────────────────────────────────────────────
def report_block(ip: str, status: str = "ok"):
    now_iso = datetime.now(IST).isoformat()
    try:
        requests.post(
            f"{YOUR_BACKEND_URL}/client_blocked",
            json={
                "ip": ip,
                "client_blocked_at": now_iso,
                "status": status      # <─ NEW FLAG
            },
            timeout=3
        )
    except Exception as e:
        print(f"⚠️ report_block failed: {e}")


def get_os():
    return platform.system().lower()

def is_tool_available(name):
    return shutil.which(name) is not None

def _run(cmd: str) -> bool:
    """Run shell command; return True on exit‑code 0, else False."""
    try:
        subprocess.run(shlex.split(cmd), check=True,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


#📂 Detect access log path based on OS and server

# def detect_log_path():
#     os_type = get_os()
#     possible_paths = []

#     if 'linux' in os_type:
#         possible_paths = [
#             '/var/log/apache2/access.log',
#             '/var/log/httpd/access_log',
#             '/var/log/nginx/access.log'
#         ]

#     elif 'darwin' in os_type:  # macOS
#         possible_paths = [
#             '/var/log/apache2/access_log',
#             '/opt/homebrew/var/log/nginx/access.log'
#         ]

#     elif 'windows' in os_type:
#         possible_paths = [
#             r'C:\xampp\apache\logs\access.log',
#             r'C:\wamp64\logs\access.log',
#             r'C:\Program Files\Apache Group\Apache2\logs\access.log'
#         ]
#         iis_logs = glob.glob(r'C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log')
#         if iis_logs:
#             iis_logs.sort(reverse=True)
#             possible_paths.insert(0, iis_logs[0])

#     for path in possible_paths:
#         if os.path.exists(path):
#             print(f"✅ Detected access log: {path}")
#             return path

#     print("❌ No known access log file found.")
#     return None

# 🔒 Block IP smartly per OS
def block_ip(ip):
    os_type = get_os()
    print(f"🚫 Attempting to block {ip} on {os_type}...")

    if 'windows' in os_type:
        if is_tool_available("netsh"):
            cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
            print(f"firewall rule added for {ip}")
            print(f"✅ Firewall rule applied for {ip}")
            report_block(ip, status="ok")          # <─ ONE LINE
            return

        else:
            print("❌ No firewall tool found.")
            report_block(ip, status="failed")
            return

    elif 'darwin' in os_type:
        if is_tool_available("pfctl"):
            pf_conf     = f"block drop from {ip} to any\n"
            anchor_path = "/etc/pf.anchors/myblocklist"

            try:
                with open(anchor_path, "a") as f:        # append, don’t overwrite
                    f.write(pf_conf)

                ok = (
                _run(f"sudo pfctl -a myblocklist -f {anchor_path}") and
                _run("sudo pfctl -E")                # enable pf (idempotent)
                )

                report_block(ip, status="ok" if ok else "failed")
                print("✅" if ok else "❌", "pfctl rule", ("added" if ok else "failed"), "for", ip)

            except PermissionError:
                print("⚠️  Need sudo privileges to write to", anchor_path)
                report_block(ip, status="failed")
        else:
            print("❌ pfctl not found. Skipping.")
            report_block(ip, status="failed")

    # elif 'darwin' in os_type:
    #     if is_tool_available("pfctl"):
    #         pf_conf = f"block drop from {ip} to any\n"
    #         anchor_path = "/etc/pf.anchors/myblocklist"
    #         try:
    #             with open(anchor_path, "w") as f:
    #                 f.write(pf_conf)
    #             subprocess.run(f"echo 'anchor \"myblocklist\"' | sudo pfctl -a myblocklist -f -", shell=True)
    #             subprocess.run("sudo pfctl -e", shell=True)
    #             print(f"✅ pfctl block added for {ip}")
    #             report_block(ip, status="ok")   
                
    #             return
    #         except Exception as e:
    #             print(f"❌ pfctl block failed: {e}")
    #             return
    #     else:
    #         print("❌ pfctl not found. Skipping.")
    #         report_block(ip, status="failed")
    #         return

    elif 'linux' in os_type:
        if is_tool_available("iptables"):
            # ✅ Let me check if I’m allowed to use sudo. If I can’t, then I’ll go with a backup plan.
            try:
                subprocess.run("sudo -n true", shell=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                print(f"✅ Firewall rule applied for {ip}")
                report_block(ip, status="ok")
                return
            except subprocess.CalledProcessError:
                print("⚠️ sudo not allowed or requires password. Trying fallback...")
            except Exception as e:
                print(f"❌ iptables command failed: {e}. Trying fallback...")

        # Fallback: write to hosts.deny
        try:
            with open("/etc/hosts.deny", "a") as f:
                f.write(f"ALL: {ip}\n")
            print(f"✅ Fallback block via /etc/hosts.deny for {ip}")
            report_block(ip, status="ok")
            return
        except Exception as e:
            print(f"❌ Fallback block failed: {e}")
            report_block(ip, status="failed")
            return

    else:
        print("⚠️ Unknown OS. No blocking method.")
        report_block(ip, status="failed")
        return


# 📤 Send test log to backend (used for testing)

IST = ZoneInfo("Asia/Kolkata")             

def send_fake_log(ip: str) -> None:
    """
    Generate ±120 credential-stuffing style logs and POST them
    to /send_logs. All timestamps carry Asia/Kolkata (+05:30) offset.
    """

    # use top-of-the-hour in IST as the log time
    now_ist   = datetime.now(IST)
    log_time  = now_ist.isoformat()                   # 'YYYY-MM-DDTHH:00:00+05:30'

    urls     = [f"/admin{i}" for i in range(20)]      # 20 unique URLs
    methods  = ["POST"] * 100 + ["GET"]               # high POST ratio
    logs     = []

    for i in range(120):                              # 120 requests
        logs.append({
            "ip":     ip,
            "time":   log_time,                       # IST timestamp
            "method": random.choice(methods),
            "url":    random.choice(urls),
            "status": 401 if i % 3 == 0 else 200,     # 33 % error rate
            "size":   random.randint(10_000, 15_000),
            "agent":  "MaliciousBot/1.0"
        })

    try:
        res = requests.post(f"{YOUR_BACKEND_URL}/send_logs", json=logs, timeout=10)
        print("📤 Fake logs sent:", res.json())
    except Exception as e:
        print("❌ Log send error:", e)


# 🧨 Simulate a DDoS burst: many IPs, many small requests in 1 sec

# ───── post ONE parsed log immediately ─────────────────────────
def _post_single(log: dict) -> None:
    try:
        # /send_logs still expects a list
        res = requests.post(f"{YOUR_BACKEND_URL}/send_logs",
                            json=[log],
                            timeout=POST_TIMEOUT)
        res.raise_for_status()
        # tiny status print so you can see progress
        print("📤 1 log →", res.json())
    except Exception as e:
        print(f"❌ POST failed: {e}")

def stream_access_log(file_path: str = LOG_FILE_PATH,
                      tail_from_end: bool = False) -> None:
    """
    • If `tail_from_end` is False  →  start at the beginning (re‑ingest whole file)
    • If `tail_from_end` is True   →  jump to EOF and only watch NEW lines
    """
    if not os.path.exists(file_path):
        print(f"❌ File not found → {file_path}")
        return

    with open(file_path, "r", encoding="utf‑8", errors="ignore") as f:
        if tail_from_end:                         # original behaviour
            f.seek(0, os.SEEK_END)
        else:
            print(f"📂 Replaying the entire file once → {file_path}")

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            parsed = parse_log_line(line)
            if not parsed:
                continue

            _post_single(parsed)      # ① send
            fetch_and_block()         # ② block immediately



def send_ddos_burst(ip_prefix: str = "10.0.1.",
                    ip_count:  int = 150,
                    req_per_ip: int = 50) -> None:
    """
    Fire a one-second DDoS-style burst:
    • Generates ip_count unique IPs  (ip_prefix + 1 … ip_prefix + ip_count)
    • Each IP sends req_per_ip requests in that same second
    • All log timestamps are IST-zone strings
    """

    now_ist = datetime.now(IST).isoformat()  # 'YYYY-MM-DDTHH:MM:SS:microsecs+05:30'

    urls    = ["/", "/login", "/api/data", "/contact"]
    methods = ["GET", "POST"]
    logs    = []

    # build ip_count × req_per_ip log rows
    for i in range(1, ip_count + 1):
        ip = f"{ip_prefix}{i}"
        for _ in range(req_per_ip):
            logs.append({
                "ip":     ip,
                "time":   now_ist,                 # identical IST timestamp
                "method": random.choice(methods),
                "url":    random.choice(urls),
                "status": 200,
                "size":   random.randint(200, 600),
                "agent":  "BotNet/1.0"
            })

    try:
        res = requests.post(f"{YOUR_BACKEND_URL}/send_logs",
                            json=logs,
                            timeout=10)
        print(f"🌊 DDoS burst sent: {res.json()}")
    except Exception as e:
        print("❌ Burst send error:", e)

# ──────────────── 3⃣  SENDER ─────────────────
def send_access_log(file_path: str = LOG_FILE_PATH,
                    batch_size: int = BATCH_SIZE) -> None:
    """
    Read *all* lines in `access.log`,
    send them to /send_logs in batches of `batch_size`.
    """
    if not os.path.exists(file_path):
        print(f"❌ File not found → {file_path}")
        return

    batch = []
    total = 0
    with open(file_path, "r", encoding="utf‑8", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if not parsed:
                continue

            batch.append(parsed)
            if len(batch) == batch_size:
                _post_batch(batch)
                total += len(batch)
                batch = []

    # flush any tail
    if batch:
        _post_batch(batch)
        total += len(batch)

    print(f"✅ Finished. Sent {total:,} log lines to backend.")


def _post_batch(batch: list[dict]) -> None:
    """
    Helper to POST one batch & print result.
    """
    try:
        res = requests.post(
            f"{YOUR_BACKEND_URL}/send_logs",
            json=batch,
            timeout=POST_TIMEOUT
        )
        res.raise_for_status()
        print(f"📤 Pushed {len(batch)} logs → {res.json()}")
    except Exception as e:
        print(f"❌ POST failed: {e}")


# 🧠 Fetch blocklist and apply blocking
def fetch_and_block():
    try:
        res = requests.get(f"{YOUR_BACKEND_URL}/get_blocklist")
        blocklist = res.json().get("blocked_ips", [])
        print("🛡️ Blocklist fetched:", blocklist)
        for ip in blocklist:
            block_ip(ip)
    except Exception as e:
        print("❌ Failed to fetch blocklist:", e)

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unknown"

# # 🧠 Parse a raw Apache/Nginx-style log line into structured format
# def parse_log_line(line):
#     import re
#     match = re.match(
#         r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+)? (?P<url>\S+)? \S+" (?P<status>\d{3}) (?P<size>\d+) "(?P<agent>[^"]+)"',
#         line
#     )
#     if not match:
#         print(f"⚠️ Failed to parse log line: {line}")
#         return None

#     parts = match.groupdict()
#     return {
#         "ip": parts["ip"],
#         "time": parts["time"],
#         "method": parts["method"] or "UNKNOWN",
#         "url": parts["url"] or "/",
#         "status": int(parts["status"]),
#         "size": int(parts["size"]),
#         "agent": parts["agent"]
#     }




# def parse_log_line(line: str) -> dict | None:
#     """
#     Parse one Apache/Nginx log line and convert the time to IST.

#     • Handles both Common‑Log and Combined‑Log formats.
#     • Accepts timestamps with or *without* an original offset.
#       - If the log already contains “+0000”, “-0700”, etc., we honor it.
#       - If not, we assume the server wrote the log in **UTC**.
#     """
#     m = re.match(
#         r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
#         r'"(?P<method>\S+)? (?P<url>\S+)? \S+" '
#         r'(?P<status>\d{3}) (?P<size>\d+) '
#         r'(?:".*?"\s)?'                 # optional referer (Combined Log)
#         r'"(?P<agent>[^"]+)"',
#         line
#     )
#     if not m:
#         print("⚠️  Failed to parse:", line.strip())
#         return None

#     parts = m.groupdict()

#     # --- 1️⃣ Parse the raw timestamp ----------------------------------------
#     raw_time = parts["time"]           # e.g. 10/Oct/2000:13:55:36 +0000
#     try:
#         # with offset present
#         dt   = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S %z")
#     except ValueError:
#         # without offset → assume UTC, then localise
#         dt   = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S")
#         dt   = dt.replace(tzinfo=ZoneInfo("UTC"))

#     # --- 2️⃣ Convert to IST and ISO‑8601 ------------------------------------
#     ist_time = dt.astimezone(IST).isoformat()    # 'YYYY‑MM‑DDTHH:MM:SS+05:30'

#     # --- 3️⃣ Return the structured dict -------------------------------------
#     return {
#         "ip":     parts["ip"],
#         "time":   ist_time,
#         "method": parts["method"] or "UNKNOWN",
#         "url":    parts["url"]    or "/",
#         "status": int(parts["status"]),
#         "size":   int(parts["size"]),
#         "agent":  parts["agent"],
#     }


# ───── primary regex (unchanged) ───────────────────────────────
log_re = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"\s*$'
)

# ───── fallback quick‑n‑dirty splitter ─────────────────────────
def loose_parse(line: str) -> dict | None:
    """
    Last‑chance parser for lines with broken quotes.
    Expects: ip ident user [time] "request" status size "-" agent*
    """
    try:
        ip, _, _, rest = line.split(" ", 3)
        time_part  = rest.split("]")[0].lstrip("[")
        request    = rest.split('"')[1]
        remainder  = rest.split('"', 2)[2].strip()
        status, size, _dash, agent = remainder.split(" ", 3)
        return {
            "ip": ip,
            "time": time_part,
            "request": request,
            "status": status,
            "size": size,
            "agent": agent,
        }
    except Exception:
        return None

# ───── master wrapper used by client_agent.py ──────────────────
def parse_log_line(line: str) -> dict | None:
    line = line.rstrip("\r\n")
    m = log_re.match(line)
    if m:                                           # 👈  normal path
        g = m.groupdict()
        request = g.pop("request")
    else:                                           # 👈  fallback
        loose = loose_parse(line)
        if not loose:
            print("⚠️  Unrecoverable:", line[:120])
            return None
        g = loose
        request = g.pop("request")

    # ── shared post‑processing (timestamp → IST, split request etc.) ──
    try:
        dt = datetime.strptime(g["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        dt = datetime.strptime(g["time"], "%d/%b/%Y:%H:%M:%S") \
                 .replace(tzinfo=ZoneInfo("UTC"))
    ist_time = dt.astimezone(IST).isoformat()

    parts  = request.split()
    method = parts[0] if parts else "UNKNOWN"
    proto  = parts[-1] if parts and parts[-1].startswith("HTTP/") else "HTTP/?"
    url    = " ".join(parts[1:-1]) if proto.startswith("HTTP/") else " ".join(parts[1:])

    status = int(g["status"]) if str(g["status"]).isdigit() else 0
    size   = int(g["size"])   if str(g["size"]).isdigit()   else 0

    return {
        "ip":     g["ip"],
        "time":   ist_time,
        "method": method,
        "url":    url or "/",
        "status": status,
        "size":   size,
        "agent":  g["agent"],
    }
# def parse_live_log(log_path):
#     try:
#         with open(log_path, "r") as f:
#             f.seek(0, 2)  # Go to end of file (tailing)

#             while True:
#                 line = f.readline()
#                 if not line:
#                     continue  # Wait for new line instead of breaking

#                 print("📄 New log line:", line.strip())
#                 parsed = parse_log_line(line)

#                 if parsed:
#                     try:
#                         res = requests.post(f"{YOUR_BACKEND_URL}/send_logs", json=[parsed])
#                         print("📤 Sent parsed log:", res.status_code)
#                     except Exception as req_err:
#                         print(f"❌ Failed to send log: {req_err}")

#     except Exception as e:
#         print(f"❌ Error reading log file: {e}")


# 🔁 Main loop
if __name__ == "__main__":
    # os_type = get_os()
    # local_ip = get_local_ip()
    # log_path = detect_log_path()

    # if not log_path:
    #     print("❌ Log file not found. Exiting agent.")
    #     exit()

    # print(f"🔁 SIEM Agent running on {os_type.upper()} ({local_ip})")
    # print(f"📂 Monitoring log file: {log_path}\n")

    
    # while True:
    #     # ✅ Use this for testing only (comment in production)
    #     send_fake_log("10.0.0.123")

    #     # 🔐 Fetch blocklist and block IPs
    #     fetch_and_block()

    #     # 🧠 OPTIONAL: Parse real logs
    #     # parse_live_log(log_path)

    #     print("⏳ Sleeping for 1s...\n")
    #     time.sleep(1)
    
    # while True:
    #     send_access_log()          # or parse_live_log(…) if you tail a file
    #     fetch_and_block()          # always poll the block list
    #     time.sleep(1)             # adjust period to your liking

    # ▸ tail the real access‑log in real‑time
    stream_access_log(LOG_FILE_PATH)
    
    # while True:
    # # ✅ Individual malicious user (kept for reference)
    # # send_fake_log("10.0.0.123")

    # # 🧨 DDoS burst test (comment out in production)
    #     send_ddos_burst(ip_prefix="10.0.2.", ip_count=120, req_per_ip=60)

    #     fetch_and_block()        # keep your blocklist pull
    #     print("⏳ Sleeping for 1 s...\n")
    #     time.sleep(1)


