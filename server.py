# server.py

# Copyright (C) 2026 Francesco Scolz
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# ================= IMPORTS =================

import os
import subprocess
import threading
import socket
import time
import logging
import requests
import ipaddress
from pathlib import Path
from collections import defaultdict, deque, Counter

import math
import statistics
import numpy as np
import sqlite3

import json
import bcrypt
from hashlib import sha256
from functools import wraps

from config import *

from flask import Flask, jsonify, request, send_from_directory, session, redirect, render_template, render_template_string


# ================= CONFIG =================

PUBLIC_ROUTES = {"/login", "/favicon.ico", "/static/Logo.png", "/static/Logo_dark.png"}
login_attempts = defaultdict(lambda: {"count": 0, "last": 0})  # track login attempts
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300 # in seconds
LOGIN_ATTEMPTS_TTL = 86400 # 24h

def _ip_stats_factory() -> dict:
    """factory function to create a new stats dictionary for an IP"""
    now = time.time()
    return {
        "max_pps": 0,
        "max_ratio": 0,
        "max_syn_count": 0,
        "max_entropy": 0,
        "min_std": None,
        "max_rst_ratio": 0,

        "packet_count": 0,
        "syn_count_fixed": 0,
        "syn_count_rstsyn": 0,
        "ack_count_fixed": 0,
        "rst_count": 0,

        "syn_ts": deque(maxlen=10000),
        "ack_ts": deque(maxlen=10000),
        "rst-ed_ts": deque(maxlen=10000),
        "timestamps": deque(maxlen=10000),

        "ports": deque(maxlen=200),
        "used_ports": [],

        "central_90_window": CAPTURE_DURATION,
        "mean_intervals": None,

        "last_seen": 0,
        "last_updated": {
            "max_pps": now,
            "max_ratio": now,
            "max_entropy": now,
            "min_std": now,
            "max_rst_ratio": now,
        },
    }

traffic = deque(maxlen=MAX_PACKETS_BUFFER)
stats_history = deque(maxlen=(GRAPH_HISTORY // CAPTURE_DURATION) + 1) # deque of historical stats snapshots for the overview graphs, with a max length based on the configured graph history and capture duration
ip_stats = defaultdict(_ip_stats_factory)  # dictionary of IPs to their stats (timestamps, ports, syn/ack flags, etc.)
lock = threading.RLock()  # lock to prevent race conditions
_login_lock = threading.Lock()  # separate lock for login attempts

graylist = {}  # list of IPs currently flagged as potential threats, with their info (score, reasons, etc.)
graylist_notified = set()  # list of notified graylisted IP (to avoid double-notifying)
watchlist = {}  # list of IPs to keep an eye on (user-defined, not necessarily malicious, but of interest), with their info (current/max of SYN/ACK ratio, entropy, pps, etc.)
whitelist = set()  # list of IPs to ignore (user-defined, e.g. trusted devices)

observed_hosts = {}  # list of hosts IPs, names and last seen
reset_times = {}  # IP-to-timestamp of last reset (pardoning) to ignore packets from before the reset
ip_service_cache = {}  # name cache for IP-based services
vendor_cache = {}  # name cache for MAC-based services
host_notes = {}  # notes for hosts, keyed by MAC when valid, IP otherwise (manually set through the UI, used for display in the observed hosts list and for user annotations)

# initialization of the app
app = Flask(__name__, static_folder="static")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False
)
app.secret_key = os.urandom(32)  # needed for session management and signing cookies

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "ids.db" # SQLite database file path, used for persistence


# ================= UTILITIES =================

def db() -> sqlite3.Connection:
    """returns a connection to the SQLite database, with WAL mode enabled for better concurrency"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def initialize_db() -> None:
    """initializes the database with the necessary tables for storing IP stats, watchlist, graylist, whitelist and notes, if they don't already exist"""
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS ip_stats (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS watchlist (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS graylist (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS whitelist (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS notes (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)
    conn.commit()
    conn.close()

def save_blob(conn: sqlite3.Connection, table: str, key: str, obj: object) -> None:
    """Save a JSON-serializable object into the specified table."""

    conn.execute(
        f"INSERT OR REPLACE INTO {table} (key, value) VALUES (?, ?)",
        (key, json.dumps(obj))
    )

def load_blob(table: str) -> dict:
    """loads a blob from the specified table in the database and returns it as a dictionary, used for loading the persisted state of saved data"""
    conn = db()
    cur = conn.execute(f"SELECT key, value FROM {table}")
    rows = cur.fetchall()
    conn.close()
    
    result = {}
    for k, v in rows:
        try:
            result[k] = json.loads(v)
        except json.JSONDecodeError:
            logging.error(f"Skipping corrupted row: key={k}")
    return result

def make_json_safe(obj: object) -> object:
    """helper function to convert objects to JSON-serializable formats"""
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    if isinstance(obj, tuple):
        return [make_json_safe(v) for v in obj]
    if isinstance(obj, set):
        return [make_json_safe(v) for v in obj]
    if isinstance(obj, deque):
        return [make_json_safe(v) for v in obj]
    if isinstance(obj, (np.integer, np.floating)):
        return obj.item()
    return obj

def restore_ip_stats(data: dict) -> defaultdict:
    """restores the ip_stats dictionary from the loaded data, converting lists back to deques"""
    result = defaultdict(_ip_stats_factory)
    for ip, s in data.items():
        s["syn_ts"] = deque(s.get("syn_ts", []), maxlen=10000)
        s["ack_ts"] = deque(s.get("ack_ts", []), maxlen=10000)
        s["rst-ed_ts"] = deque(s.get("rst-ed_ts", []), maxlen=10000)
        s["ports"] = deque(s.get("ports", []), maxlen=200)
        s["timestamps"] = deque(s.get("timestamps", []), maxlen=10000)
        result[ip] = s
    return result

def persistence_loop() -> None:
    """background loop to save important data for persistence across restarts"""

    while True:
        # Snapshot in RAM under lock
        with lock:
            watchlist_snapshot = {
                ip: make_json_safe(data)
                for ip, data in watchlist.items()
            }
            graylist_snapshot = {
                ip: make_json_safe(data)
                for ip, data in graylist.items()
            }
            ip_stats_snapshot = {
                ip: make_json_safe(data)
                for ip, data in ip_stats.items()
            }
            whitelist_snapshot = set(whitelist)
            notes_snapshot = dict(host_notes)

            config_snapshot = {
                "THRESHOLDS": make_json_safe(THRESHOLDS),
                "PENALTIES": make_json_safe(PENALTIES),
            }

        # DB I/O outside lock
        conn = db()

        # save blobs
        try: 
            # watchlist
            for ip, data in watchlist_snapshot.items():
                save_blob(conn, "watchlist", ip, data)
            # graylist
            for ip, data in graylist_snapshot.items():
                save_blob(conn, "graylist", ip, data)
            # ip stats
            for ip, data in ip_stats_snapshot.items():
                save_blob(conn, "ip_stats", ip, data)
            # whitelist
            for ip in whitelist_snapshot:
                save_blob(conn, "whitelist", ip, True)
            # notes
            for key, value in notes_snapshot.items():
                save_blob(conn, "notes", key, value)
            # config
            save_blob(conn, "config", "THRESHOLDS", config_snapshot["THRESHOLDS"])
            save_blob(conn, "config", "PENALTIES", config_snapshot["PENALTIES"])
        

            cleanups = {
                "ip_stats": list(ip_stats_snapshot.keys()),
                "watchlist": list(watchlist_snapshot.keys()),
                "graylist": list(graylist_snapshot.keys()),
                "whitelist": list(whitelist_snapshot),
                "notes": list(notes_snapshot.keys())
            }

            for table, keys in cleanups.items(): # clean entries no longer in the current state
                if keys:
                    conn.execute(
                        "DELETE FROM {} WHERE key NOT IN ({})".format(table, ",".join("?" * len(keys))),
                        keys
                    )
                else:
                    conn.execute(f"DELETE FROM {table}")
            
            conn.commit()
                
        except Exception as e:
            logging.error(f"Error in persistence loop: {e}")
        finally:
            conn.close()

        time.sleep(300) # change if needed

def check_hash(plain: str, hashed: str) -> bool:
    """checks if the provided plain text username/password matches the hashed password stored in the config, used for authentication in the login route"""
    return bcrypt.checkpw(sha256(plain.encode("utf-8")).hexdigest().encode(), hashed.encode())

def login_required(f: callable) -> callable:
    """decorator to protect routes that require authentication, checks if the user is logged in by looking at the session while checking for session timeout to automatically log out users after a period of inactivity"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return "Unauthorized", 401

        if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
            session.clear()
            return (
                "Session expired",
                401,
            ) 
        session["last_active"] = time.time()
        return f(*args, **kwargs)

    return decorated

def get_local_ip() -> str:
    """utility function to get the local IP address of the machine, used for Telegram notifications if the server IP is not configured in the .env file, this is done by creating a temporary socket connection to a public IP address (1.1.1.1)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

SERVER_IP = IP if IP else get_local_ip()

def send_telegram_message(message: str) -> None:
    """sends a message to the configured Telegram chat using the Bot API, used for sending alerts when new IPs are added to the graylist"""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=3)
    except Exception as e:
        print("Telegram notification failed:", e)

def is_valid_ipv4(ip: str) -> bool:
    try:
        adr = ipaddress.ip_address(ip)
        if adr.version == 4:
            return True
        else:
            return False # IPv6, not currently supported
    except ValueError:
        return False # not a valid IP address

def is_private_ip(ip: str) -> bool:
    """returns True if the IP is private (local network), False otherwise"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_ip_service(ip: str) -> str:
    """returns a name for the IP based on reverse DNS or external API, with caching"""
    now = time.time()
    to_remove = [ # remove cache older than HOSTS_WINDOW_SECONDS
        i
        for i, v in ip_service_cache.items()
        if now - v["last_seen"] > HOSTS_WINDOW_SECONDS
    ]
    for i in to_remove:
        del ip_service_cache[i]

    if ip in ip_service_cache:
        ip_service_cache[ip]["last_seen"] = now
        return ip_service_cache[ip]["service"]

    # try reverse DNS lookup first, if fails try external API, if that fails return "-"
    try:
        service = socket.gethostbyaddr(ip)[0]
    except Exception:
        try:
            res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            service = res.json().get("org", "-") if res.status_code == 200 else "-"
        except Exception:
            service = "-"

    ip_service_cache[ip] = {"service": service, "last_seen": now}
    return service

def get_vendor(mac: str) -> str:
    """returns a vendor name for the given MAC address using an external API or caching"""
    now = time.time()
    to_remove = [ # remove cache older than HOSTS_WINDOW_SECONDS
        m
        for m, v in vendor_cache.items()
        if now - v["last_seen"] > HOSTS_WINDOW_SECONDS
    ]
    for m in to_remove:
        del vendor_cache[m]

    mac = mac.lower().replace("-", ":")

    if mac in vendor_cache:
        vendor_cache[mac]["last_seen"] = now
        return vendor_cache[mac]["vendor"]

    # try external API, if fails return "Unknown"
    try:
        res = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        vendor = res.text.strip() if res.status_code == 200 else "Unknown"
    except Exception:
        vendor = "Unknown"

    vendor_cache[mac] = {"vendor": vendor, "last_seen": now}
    return vendor

def entropy(ports: list) -> float:
    """calculates shannon entropy of a list of ports (used to detect port scans)"""
    if not ports:
        return 0

    counts = Counter(ports)
    total = sum(counts.values())

    E = 0
    for c in counts.values(): # formula for Shannon entropy
        p = c / total
        E -= p * math.log2(p)

    return E

def recalc_graylist_scores():
    """Recalculate scores and remove IPs below alert threshold."""
    with lock:
        min_score = PENALTIES["Minimum score for alert"]

        for ip, info in list(graylist.items()):
            reasons = info.get("reasons", [])

            score = 0
            for r in reasons:
                if r in PENALTIES:
                    score += PENALTIES[r]
            info["score"] = score

            if score < min_score:
                del graylist[ip]
                graylist_notified.discard(ip)  # make the IP notifiable again


# ================= CAPTURE AND ANALYZE =================

def analyze_traffic(new_packets):
    """
    Analyzes the captured traffic to update the graylist and watchlist, calculates metrics for each IP and determines if they should be flagged as potential threats based on the defined thresholds and penalties, also handles notifications for new flagged IPs and updates the stats for display in the UI
    The function processes each new packet, updates the stats for the source IP, and then iterates through all IPs to calculate their scores and update the graylist accordingly. It also detects new IPs that have been added to the graylist since the last analysis to send notifications for them.
    """

    # Load thresholds from config
    PPS_THRESHOLD = THRESHOLDS["pps_threshold"]
    SYN_ACK_RATIO_THRESHOLD = THRESHOLDS["synack_threshold"]
    MAX_PORT_ENTROPY = THRESHOLDS["entropy_threshold"]
    MIN_SYN_COUNT = THRESHOLDS["min_syn_count"]
    MAX_STD_INTERVALS = THRESHOLDS["max_std_timestamp"]
    RST_RATIO_THRESHOLD = THRESHOLDS["rstsyn_ratio"]
    MIN_RST_COUNT = THRESHOLDS["min_rst_count"]

    now = time.time()

    # cleanup old entries for every ip
    for ip, s in ip_stats.items():
        for deque_key in ["syn_ts", "ack_ts", "rst-ed_ts"]:
            while s[deque_key] and now - s[deque_key][0] > RECENT_HISTORY_TIMEFRAME:
                s[deque_key].popleft()
        while s["ports"] and now - s["ports"][0][1] > RECENT_HISTORY_TIMEFRAME:
            s["ports"].popleft()
        while s["timestamps"] and now - s["timestamps"][0] > CAPTURE_DURATION:
            s["timestamps"].popleft()

    for pkt in new_packets:
        ip = pkt.get("src_ip")
        if not is_valid_ipv4(ip):  # skip packets without valid IPs (sometimes tshark can output malformed IPs or empty fields)
            continue
        if (ip in reset_times and pkt["ts"] < reset_times[ip]):  # skip packets from before the last reset time for this IP
            continue
        
        # get stats for this IP, initialize if not present
        if ip not in ip_stats:
            ip_stats[ip] = _ip_stats_factory()

        s = ip_stats[ip]
        ts = pkt["ts"]
        s["timestamps"].append(ts)

        ### METRIC CALCULATION

        s["last_seen"] = ts

        # Port extraction

        port = None

        ports = pkt.get("ports", [])
        if len(ports) > 1:

            try:
                port = int(ports[1])  # get destination port
            except:
                port = None

            if (port is not None and port < EPHEMERAL_PORT_THRESHOLD):
                s["ports"].append((port, ts))

        # SYN/ACK flags
        if pkt.get("flags"):
            try:
                flags = int(pkt["flags"], 16)

                if flags & 0x02 and not (flags & 0x10):  # pure SYN
                    s["syn_ts"].append(ts)

                if flags & 0x10 and not (flags & 0x02):  # pure ACK
                    s["ack_ts"].append(ts)
                
                if flags & 0x04:  # RST flag
                    rst_dst = pkt.get("dst_ip")  # add RST flag to the attacker
                    if rst_dst in ip_stats:
                        ip_stats[rst_dst]["rst-ed_ts"].append(ts)
            except:
                pass


    # GRAYLIST UPDATE

    for ip, s in ip_stats.items():
        if (not s["timestamps"] or len(s["timestamps"]) <= 2):
            continue  # skip IPs with too little activity to analyze
        
        latest_ts = s["timestamps"][-1]
        percentile = 90 # used to detect Xth central percentile of the timestamps window, to separate bursts from sustained activity (90th by default, change if needed)
        high_percentile = percentile + (100 - percentile)/2
        low_percentile = (100 - percentile)/2

        recent_ts_arr = np.array([t for t in s["timestamps"] if latest_ts - t <= CAPTURE_DURATION])

        ### METRIC CALCULATION

        # PPS
        pps = len(recent_ts_arr) / CAPTURE_DURATION
        # SYN/ACK ratio
        syn_count = len(s["syn_ts"])
        ack_count = len(s["ack_ts"])
        ratio = syn_count / max(1, ack_count)
        # Port entropy
        entropy_val = entropy([p[0] for p in s["ports"]])
        # Std intervals
        intervals = [t2 - t1 for t1, t2 in zip(recent_ts_arr, recent_ts_arr[1:])]
        std_val = statistics.stdev(intervals) if len(intervals) > 2 else None
        # RST/SYN ratio
        rst_count = len(s["rst-ed_ts"])
        rst_ratio = rst_count / max(1, syn_count)

        # Update metrics only if they are "worse"

        # PPS
        if round(pps, 1) > s.get("max_pps", 0):
            s["max_pps"] = round(pps, 1)
            s["last_updated"]["max_pps"] = now
            if (len(recent_ts_arr) >= 2):
                central_90_window = np.percentile(recent_ts_arr, high_percentile) - np.percentile(recent_ts_arr, low_percentile)
            else:
                central_90_window = CAPTURE_DURATION
            s["central_90_window"] = round(central_90_window, 3)
            s["packet_count"] = len(recent_ts_arr)

        # SYN/ACK ratio
        if round(ratio, 2) > s.get("max_ratio", 0):
            s["max_ratio"] = round(ratio, 2)
            # we store the syn_count and ack_count at the moment we see the new max ratio
            s["syn_count_fixed"] = syn_count
            s["ack_count_fixed"] = ack_count
            if syn_count > s.get("max_syn_count", 0): # to also mantain SYN count for the moment we see the new max ratio, as it's a condition for flagging SYN floods
                s["max_syn_count"] = syn_count
            s["last_updated"]["max_ratio"] = now

        # Entropy
        if round(entropy_val, 2) > s.get("max_entropy", 0):
            ports_only = [p[0] for p in s["ports"]]
            s["max_entropy"] = round(entropy_val, 2)
            s["last_updated"]["max_entropy"] = now
            s["used_ports"] = [p for p, _ in Counter(ports_only).most_common()] # sort by frequency
            
        # Std of intervals
        if std_val is not None and (s.get("min_std") is None or round(std_val, 4) < s["min_std"]):
            s["min_std"] = round(std_val, 4)
            s["last_updated"]["min_std"] = now
            s["mean_intervals"] = round(statistics.mean(intervals), 4) if intervals else None
        
        # RST/SYN ratio
        if round(rst_ratio, 2) > s["max_rst_ratio"] and rst_count >= MIN_RST_COUNT:
            s["max_rst_ratio"] = round(rst_ratio, 2)
            s["rst_count"] = rst_count
            s["syn_count_rstsyn"] = syn_count
            s["last_updated"]["max_rst_ratio"] = now

        # REASONS AND SCORE
        reasons = []
        if s["max_pps"] >= PPS_THRESHOLD:
            reasons.append("Packet flood")
        if (s.get("max_syn_count", 0) >= MIN_SYN_COUNT and s["max_ratio"] >= SYN_ACK_RATIO_THRESHOLD):  # only if we have at least a minimum number of SYN packets
            reasons.append("SYN flood")
        if s["max_entropy"] >= MAX_PORT_ENTROPY:
            reasons.append("Port scan")
        if s.get("min_std") and s["min_std"] < MAX_STD_INTERVALS:
            reasons.append("Regular intervals")
        if (s["rst_count"] >= MIN_RST_COUNT and s["max_rst_ratio"] >= RST_RATIO_THRESHOLD): # only if we have at least a minimum number of RST packets
            reasons.append("Connection probing")

        score = sum(PENALTIES[r] for r in reasons if r in PENALTIES)

        if (score >= PENALTIES.get("Minimum score for alert", 5) and ip not in whitelist and "," not in ip):
            graylist[ip] = { # add to graylist
                "score": score,
                "reasons": reasons,
                "ratio": round(s["max_ratio"], 2),
                "entropy": round(s["max_entropy"], 2),
                "max_pps": round(s["max_pps"], 1),
                "std_intervals": round(s["min_std"], 4) if s.get("min_std") else None,
                "last_updated": s["last_updated"],
                "central_90_window": s["central_90_window"],
                "syn_count": s["syn_count_fixed"],
                "syn_count_rstsyn": s["syn_count_rstsyn"],
                "ack_count": s["ack_count_fixed"],
                "used_ports": s["used_ports"],
                "mean_intervals": s["mean_intervals"],
                "rst_ratio": round(s["max_rst_ratio"], 2),
                "rst_count": s["rst_count"],
                "packet_count": s["packet_count"],
            }

    recalc_graylist_scores()


    # WATCHLIST UPDATE

    for ip in watchlist:
        if (ip not in ip_stats):
            watchlist[ip]["pps_current"] = 0
            watchlist[ip]["ratio_current"] = 0
            watchlist[ip]["entropy_current"] = 0
            watchlist[ip]["std_current"] = None
            watchlist[ip]["rst_ratio_current"] = 0
            continue

        s = ip_stats[ip]
        w = watchlist[ip]

        
        ### METRIC CALCULATION

        # PPS
        pps = len(s["timestamps"]) / CAPTURE_DURATION
        # SYN/ACK ratio
        syn_count = len(s["syn_ts"])
        ack_count = len(s["ack_ts"])
        ratio = syn_count / max(1, ack_count)
        # Port entropy
        entropy_val = entropy([p[0] for p in s["ports"]])
        # Std intervals
        if len(s["timestamps"]) <= 2:
            std_val = None
        else:
            latest_ts_w  = s["timestamps"][-1]
            recent_ts_arr_w  = np.array([t for t in s["timestamps"] if latest_ts_w - t <= CAPTURE_DURATION])
            intervals = [t2 - t1 for t1, t2 in zip(recent_ts_arr_w, recent_ts_arr_w[1:])]
            std_val = statistics.stdev(intervals) if len(intervals) > 2 else None
        # RST/SYN ratio
        rst_count = len(s["rst-ed_ts"])
        rst_ratio = rst_count / max(1, syn_count)
        

        if "first_seen" not in w:
            w["first_seen"] = now

        if "last_updated" not in w:
            w["last_updated"] = {
                "max_ratio": now,
                "max_entropy": now,
                "min_std": now,
                "max_pps": now,
                "max_rst_ratio": now
            }  # default to now

        # Update metrics only if they are "worse"

        # PPS
        if pps > w["max_pps"]:
            w["max_pps"] = round(pps, 1)
            w["last_updated"]["max_pps"] = now
            w["central_90_window"] = s.get("central_90_window", CAPTURE_DURATION)
            w["packet_count"] = len(s["timestamps"])
        w["pps_current"] = round(pps, 1)

        # Ratio
        if ratio > w["max_ratio"] and syn_count >= MIN_SYN_COUNT:
            w["max_ratio"] = round(ratio, 2)
            w["last_updated"]["max_ratio"] = now
            w["syn_count"] = syn_count
            w["ack_count"] = ack_count
        w["ratio_current"] = round(ratio, 2)

        # Entropy
        if entropy_val > w["max_entropy"]:
            w["max_entropy"] = round(entropy_val, 2)
            w["last_updated"]["max_entropy"] = now
            w["used_ports"] = s["used_ports"]
        w["entropy_current"] = round(entropy_val, 2)

        # Std intervals
        if std_val is not None:
            if w["min_std"] is None or std_val < w["min_std"]:
                w["min_std"] = round(std_val, 4)
                w["last_updated"]["min_std"] = now
                w["mean_intervals"] = s["mean_intervals"]
        w["std_current"] = round(std_val, 4) if std_val is not None else None
    
        # RST/SYN ratio
        if rst_ratio > w["max_rst_ratio"] and rst_count >= MIN_RST_COUNT:
            w["max_rst_ratio"] = round(rst_ratio, 2)
            w["rst_count"] = rst_count
            w["syn_count_rstsyn"] = syn_count
            w["last_updated"]["max_rst_ratio"] = now
        w["rst_ratio_current"] = round(rst_ratio, 2)


    # Cleanup of ip_stats > HOSTS_WINDOW_SECONDS
    to_delete = [ip for ip, s in ip_stats.items() if now - s["last_seen"] > HOSTS_WINDOW_SECONDS]
    for ip in to_delete:
        if (ip not in watchlist and ip not in graylist):  # only remove IPs if not in watchlist or graylist
            del ip_stats[ip]


def capture_and_analyze_loop():
    """Main loop to capture traffic with tshark, parse it, update the shared traffic list and observed hosts, and call the analyze_traffic function to update the graylist, watchlist and stats."""
    global traffic, stats_history

    while True:
        # command to execute
        cmd = [
            "tshark",
            "-l",
            "-i",
            IFACE,  # interface on which to capture packets on
            "-a",
            f"duration:{CAPTURE_DURATION}",  # time duration of the capture
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",  # timestamp
            "-e",
            "frame.len",  # packet lenght
            "-e",
            "eth.src",  # source MAC
            "-e",
            "eth.dst",  # destination MAC
            "-e",
            "ip.src",  # source IP
            "-e",
            "ip.dst",  # destination IP
            "-e",
            "tcp.flags",  # TCP flags (e.g. SYN, ACK...)
            "-e",
            "tcp.srcport",  # TCP source port
            "-e",
            "tcp.dstport",  # TCP destination PORT
            "-e",
            "udp.srcport",  # UDP source PORT
            "-e",
            "udp.dstport",  # UDP destination PORT
            "-E",
            "separator=|",
            "-Y",
            "ip.version == 4 and not ip.addr == 127.0.0.1",  # IPv4 only and not from localhost
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=CAPTURE_DURATION + 5,  # buffer time in case tshark takes a bit longer
            )
        except Exception as e:
            print(f"tshark ERROR: {e}")
            continue
        if proc.returncode != 0:
            print("tshark failed →", proc.stderr.strip())
            continue

        ### PARSE OUTPUT
        new_packets = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if (len(parts) < 9):  # we need at least 9 fields (timestamp, length, src MAC, dst MAC, src IP, dst IP, flags, src port, dst port)
                continue

            try:
                ts = float(parts[0])
            except ValueError:
                continue

            new_packets.append(
                {
                    "ts": ts,
                    "src_ip": parts[4],
                    "dst_ip": parts[5],
                    "src_mac": parts[2],
                    "dst_mac": parts[3],
                    "flags": parts[6],
                    "ports": [p for p in parts[7:11] if p.isdigit()],
                }
            )

        # resolve names for observed hosts (outside lock)
        name_resolution = {}
        for pkt in new_packets:
            mac = pkt.get("src_mac", "")
            ip  = pkt.get("src_ip",  "")
            if not ip or "," in ip or ip == "127.0.0.1":
                continue
            if is_private_ip(ip):
                if mac:
                    key = ("vendor", mac)
                    if key not in name_resolution:
                        name_resolution[key] = get_vendor(mac)
            else:
                key = ("service", ip)
                if key not in name_resolution:
                    name_resolution[key] = get_ip_service(ip)


        # update shared data structures with lock
        with lock:
            traffic.extend(new_packets)
            new_packets_copy = list(new_packets)  # copy for analyze_traffic use

            # update observed hosts with the new packets
            now = time.time()
            for pkt in new_packets:
                mac = pkt.get("src_mac")
                ip = pkt.get("src_ip")
                if not mac or not ip:
                    continue
                if (ip in ("127.0.0.1") or "," in ip):  # skip localhost and malformed IPs (sometimes tshark can output multiple IPs separated by commas for some packets)
                    continue

                if is_private_ip(ip):
                    # LOCAL host → name based on MAC address
                    if not mac:
                        mac = "-"
                        vendor = "-"
                    else:
                        vendor = name_resolution.get(("vendor", mac), "-")
                else:
                    # EXTERNAL host → name based on IP address
                    mac = "-"
                    vendor = name_resolution.get(("service", ip), "-")

                # find an existing host with the same MAC
                existing_key = None
                for key in observed_hosts.keys():
                    existing_mac = key.split("_")[0]
                    if (existing_mac == mac and mac != "-"):  # we also check that the MAC is not "-" because that means we don't have a valid MAC for this host and we don't want to mix different hosts with invalid MACs together
                        existing_key = key
                        break

                # check for IP conflicts: if the same IP is associated with a different MAC address, we have a conflict and we don't add the new host to avoid mixing different hosts together (e.g. in case of DHCP churn or spoofing)
                ip_conflict = False
                for key, info in observed_hosts.items():
                    existing_mac = key.split("_")[0]
                    if info["last_ip"] == ip and existing_mac != mac:
                        ip_conflict = True
                        break

                if ip_conflict:
                    continue

                # if we have an existing host with the same MAC, we update its IP, last seen time and vendor
                if existing_key:
                    observed_hosts[existing_key]["last_ip"] = ip
                    observed_hosts[existing_key]["last_seen"] = now
                    observed_hosts[existing_key]["name"] = vendor

                    new_key = f"{mac}_{ip}"
                    if (new_key != existing_key):  # changes the key to include updated MAC and IP
                        observed_hosts[new_key] = observed_hosts.pop(existing_key)

                # if there's no type of conflict, simply add a new host
                else:
                    observed_hosts[f"{mac}_{ip}"] = {
                        "last_ip": ip,
                        "last_seen": now,
                        "name": vendor,
                    }


            for key in list(observed_hosts.keys()): # remove old hosts
                if now - observed_hosts[key]["last_seen"] > HOSTS_WINDOW_SECONDS:
                    del observed_hosts[key]

            analyze_traffic(new_packets_copy)  # analyze traffic

            # get snapshot of current stats for overview chart
            this_snapshot = {
                "ts": int(time.time()),
                "packets": len(new_packets),
                "pps": round(len(new_packets) / CAPTURE_DURATION, 1),
            }

            stats_history.append(this_snapshot)

            to_notify = [ # prepare list of new graylisted IPs to notify about (in lock)
                (ip, graylist[ip]["reasons"])
                for ip in graylist
                if ip not in graylist_notified
            ]
            graylist_notified.update(ip for ip, _ in to_notify)

        for ip, reasons in to_notify: # notify new graylisted IPs outside of the lock
            if USE_TELEGRAM:
                    reasons_str = " / ".join(reasons)
                    message = f"⚠️ NEW GRAYLISTED! ⚠️\n*{ip}* ({reasons_str})\n\nName: {get_ip_service(ip)}\nCheck at http://{SERVER_IP}:{PORT}\n\nMore info at:\n- https://ipinfo.io/{ip}\n- https://www.abuseipdb.com/check/{ip}"
                    send_telegram_message(message)


# =================== ROUTES ===================

@app.before_request # before any requests, check for login
def require_login():
    path = request.path

    if path.startswith("/api/") or path == "/logout":
        return  # pass, decorator will handle authentication for APIs and logout

    if not any(path.startswith(r) for r in PUBLIC_ROUTES):
        if not session.get("logged_in"):
            return redirect("/login")
        if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
            session.clear()
            return redirect("/login")
        session["last_active"] = time.time()

@app.route("/")  # home route, serves the main page of the UI
@login_required
def index():
    return send_from_directory("static", "index.html")

@app.route("/login", methods=["GET", "POST"])  # login route: if GET, serve the login page, if POST, check the credentials and if correct, set the session as logged in and redirect to home, otherwise show an error message
def login():

    LOGIN_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="it">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>IDS Login</title>
            <link rel="icon" href="/favicon.ico" type="image/x-icon">

            <style>
                :root {
                    --bg: #f8f9fa;
                    --card: #ffffff;
                    --text: #212529;
                    --border: #dee2e6;
                    --accent: #6c757d;
                    --danger: #dc3545;
                }

                body.dark-theme {
                    --bg: #121212;
                    --card: #1e1e1e;
                    --text: #e9ecef;
                    --border: #2c2c2c;
                    --accent: #868e96;
                    --danger: #ff6b6b;
                }

                * {
                box-sizing: border-box;
                }

                body {
                    margin: 0;
                    height: 100vh;

                    display: flex;
                    justify-content: center;
                    align-items: center;

                    background: var(--bg);
                    color: var(--text);

                    font-family: system-ui, sans-serif;
                }


                h2 {
                    margin-top: 0;
                    margin-bottom: 18px;
                    text-align: center;
                }

                input[type="text"],
                input[type="password"] {
                    width: 100%;

                    padding: 10px 12px;
                    margin-bottom: 12px;

                    border-radius: 8px;
                    border: 1px solid var(--border);

                    background: transparent;
                    color: var(--text);

                    outline: none;
                }

                input:focus {
                    border-color: var(--accent);
                }

                input[type="submit"] {
                    width: 100%;

                    padding: 10px 12px;

                    border: none;
                    border-radius: 8px;

                    background: var(--accent);
                    color: white;

                    cursor: pointer;
                    font-weight: 600;
                }

                input[type="submit"]:hover {
                    opacity: 0.9;
                }

                .error {
                    color: var(--danger);
                    margin-bottom: 10px;
                    text-align: center;
                    font-size: 0.9rem;
                }

                .hint {
                    margin-top: 12px;
                    text-align: center;
                    font-size: 0.75rem;
                    color: var(--text);
                    opacity: 0.6;
                }

                .container {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 14px;
                }

                .logo {
                    width: 148px;
                    height: 148px;
                    margin-bottom: 12px;
                    display: block;
                }

                .login-box {
                    width: 400px;

                    background: var(--card);
                    border: 1px solid var(--border);
                    border-radius: 12px;

                    padding: 24px;
                }

                #theme-btn {
                    position: fixed;
                    bottom: 16px;
                    right: 16px;
                    background: var(--card);
                    color: var(--text);
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    padding: 8px 12px;
                    cursor: pointer;
                    font-size: 0.85rem;
                }
            </style>
        </head>

        <body>
            <div class="container">
                <a href="https://github.com/FreyFlyy/light-ids" target="_blank" rel="noopener">
                    <img class="logo">
                </a>

                <div class="login-box">
                    <h2>IDS Login</h2>

                    <form method="post">
                        <div class="error">{{ error }}</div>

                        <input type="text" name="username" placeholder="Username" required autofocus>
                        <input type="password" name="password" placeholder="Password" required>

                        <input type="submit" value="Login">
                    </form>
                </div>
            </div>

        <button id="theme-btn" onclick="toggleTheme()">Light ☀️</button>

        <script>
            const btn = document.getElementById('theme-btn');
            const logo = document.querySelector('.logo');
            const saved = localStorage.getItem('theme');

            function applyTheme(dark) {
                document.body.classList.toggle('dark-theme', dark);
                btn.textContent = dark ? 'Light ☀️' : 'Dark 🌙';
                logo.src = dark ? '/static/Logo_dark.png' : '/static/Logo.png';
            }

            applyTheme(saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches));

            function toggleTheme() {
                const isDark = document.body.classList.contains('dark-theme');
                localStorage.setItem('theme', isDark ? 'light' : 'dark');
                applyTheme(!isDark);
            }
        </script>

        </body>
        </html>
        """

    if request.method == "GET": # if GET request, render the login page
        return render_template_string(LOGIN_TEMPLATE, error="")


    error = ""
    ip = request.remote_addr
    
    with _login_lock: # handle login attempts (POST) with a lock

        # cleanup old login attempts
        now = time.time()
        stale = [k for k, v in login_attempts.items()
                if now - v["last"] > LOGIN_ATTEMPTS_TTL]
        for k in stale:
            del login_attempts[k]

        
        attempt = login_attempts[ip]

        if attempt["count"] >= MAX_ATTEMPTS:
            if time.time() - attempt["last"] < LOCKOUT_TIME:
                return "Too many attempts", 429
            else:
                attempt["count"] = 0  # reset after lockout

        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if check_hash(username, IDS_USERNAME) and check_hash(password, IDS_PASSWORD):
                attempt["count"] = 0
                session["logged_in"] = True
                session["last_active"] = time.time()
                return redirect("/")
            else:
                attempt["count"] += 1
                attempt["last"] = time.time()
            error = "Username or password incorrect"

    return render_template_string(LOGIN_TEMPLATE, error=error)
        

@app.route("/logout", methods=["POST"])  # logout route to clear the session and log the user out
@login_required
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/config")  # API route to get the current configuration values (thresholds, penalties, capture settings, etc.) for display in the frontend
@login_required
def get_config():
    return jsonify(
        {
            "THRESHOLDS": THRESHOLDS,
            "PENALTIES": PENALTIES,
            "IFACE": IFACE,
            "PORT": PORT,
            "CAPTURE_DURATION": CAPTURE_DURATION,
            "MAX_PACKETS_BUFFER": MAX_PACKETS_BUFFER,
            "GRAPH_HISTORY": GRAPH_HISTORY,
            "RECENT_HISTORY_TIMEFRAME": RECENT_HISTORY_TIMEFRAME,
            "HOSTS_WINDOW_SECONDS": HOSTS_WINDOW_SECONDS,
        }
    )

@app.route("/api/hosts")  # API route to get the list of observed hosts with their info (IP, MAC, name, status), used to populate the hosts overview table in the UI
@login_required
def api_hosts():
    now = time.time()
    hosts = []

    with lock:
        for key, info in observed_hosts.items():
            if (now - info["last_seen"] > HOSTS_WINDOW_SECONDS): # skip old hosts
                continue

            ip = info["last_ip"]
            mac = key.split("_")[0]
            name = info.get("name", "-")

            last_seen = info["last_seen"]
            score = graylist.get(ip, {}).get("score", 0)

            note = host_notes.get(mac, host_notes.get(ip, ""))

            hosts.append(
                {
                    "mac": mac,
                    "name": name,
                    "last_ip": ip,
                    "last_seen": last_seen,
                    "score": score,
                    "note": note,
                }
            )

    return jsonify(hosts)

@app.route("/api/hosts/note", methods=["POST"])  # API route to save a custom note for a host, identified by either its MAC or IP address
@login_required
def save_host_note():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip()
    ip = data.get("ip", "").strip()
    note = data.get("note", "").strip()

    with lock:
        if note == "":  # if note is empty, remove existing note for this host
             host_notes.pop(mac, None)
             host_notes.pop(ip, None)
             return jsonify({"success": True})
        if mac != "" and mac != "-":  # use MAC keying if valid and not "-" (local)
            host_notes[mac] = note
        elif ip != "" and ip != "-":  # else use IP keying if valid and not "-" (not local)
            host_notes[ip] = note
        else:
            return jsonify({"error": "missing identifier"}), 400

    return jsonify({"success": True})

@app.route("/favicon.ico")  # route to serve the favicon
def favicon():
    return send_from_directory("static", "favicon.ico")

@app.route("/api/stats") # API route to get the current stats for display in the overview charts in the UI, including PPS and top sources
@login_required
def api_stats():
    with lock:
        now = time.time()

        recent_stats = [ # only include stats from the last GRAPH_HISTORY seconds for the overview chart
            p for p in stats_history
            if p["ts"] >= now - GRAPH_HISTORY
        ]

        top_sources = Counter( # get top source IPs
            p["src_ip"]
            for p in traffic
            if p["src_ip"] and "." in p["src_ip"] and not "," in p["src_ip"]
        ).most_common(10)

        return jsonify({
            "stats": recent_stats,
            "top_sources": top_sources
        })
    
@app.route("/api/thresholds", methods=["GET"])  # API route to get the current metric thresholds for anomaly detection
@login_required
def get_thresholds():
    return jsonify(THRESHOLDS)

@app.route("/api/thresholds", methods=["POST"])  # API route to update the current metric thresholds for anomaly detection
@login_required
def update_thresholds():
    data = request.json or {}
    updated = False
    with lock:
        for key in THRESHOLDS:
            if key in data:
                try:
                    THRESHOLDS[key] = float(data[key])
                    updated = True
                except ValueError:
                    pass  # if conversion fails keep the old value

        if updated:
            recalc_graylist_scores()

        return jsonify(THRESHOLDS)

@app.route("/api/penalties", methods=["GET"])  # API route to get the current penalties for each motivation
@login_required
def get_penalties():
    return jsonify(PENALTIES)

@app.route("/api/penalties", methods=["POST"])  # API route to update the current penalties for each motivation
@login_required
def update_penalties():
    global PENALTIES
    data = request.json or {}
    updated = False
    with lock:
        for key in data:
            try:
                PENALTIES[key] = float(data[key])
                updated = True
            except ValueError:
                pass  # if conversion fails keep the old value 

        if updated:
            recalc_graylist_scores()

        return jsonify(PENALTIES)

@app.route("/api/graylist")  # API route to get the current graylist with the flagged IPs and their info (score, reasons, metrics values...)
@login_required
def api_graylist():
    with lock:
        return jsonify(graylist)

@app.route("/api/reset", methods=["POST"])  # reset an IP, effectively "pardoning" it for everything done until that point
@login_required
def reset_IP():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "missing IP"}), 400
    if not is_valid_ipv4(ip):
        return jsonify({"error": "invalid IP format"}), 400

    with lock:
        now = time.time()

        reset_times[ip] = now

        graylist.pop(ip, None)
        graylist_notified.discard(ip)
        ip_stats.pop(ip, None)
        w = watchlist.get(ip)
        if w:
            watchlist[ip] = { # reset watchlist metrics for this IP, but keep it in the watchlist
                "ratio_current": 0,
                "max_ratio": 0,
                "entropy_current": 0,
                "max_entropy": 0,
                "std_current": None,
                "min_std": None,
                "pps_current": 0,
                "max_pps": 0,
                "first_seen": now,
                "central_90_window": CAPTURE_DURATION,
                "syn_count": 0,
                "syn_count_rstsyn": 0,
                "ack_count": 0,
                "used_ports": [],
                "mean_intervals": None,
                "max_rst_ratio": 0,
                "rst_ratio_current": 0,
                "rst_count": 0,
                "packet_count": 0,
                "last_updated": {
                    "max_ratio": now,
                    "max_entropy": now,
                    "min_std": now,
                    "max_pps": now,
                    "max_rst_ratio": now
                },
            }


        # remove old reset markers
        to_remove = [
            k for k, t in reset_times.items() if now - t > HOSTS_WINDOW_SECONDS
        ]
        for k in to_remove:
            del reset_times[k]
            
        current_graylist = ", ".join(graylist.keys()) if graylist else "-"
    if USE_TELEGRAM:
        send_telegram_message(f"✅ IP reset: {ip}\nCurrent graylist: {current_graylist}\n\nNot you? Check immediately at http://{SERVER_IP}:{PORT}, change password and restart the service")
    return jsonify({"ok": True})

@app.route("/api/whitelist")  # API route to get the current whitelist
@login_required
def api_whitelist():
    with lock:
        return jsonify(list(whitelist))

@app.route("/api/whitelist/add", methods=["POST"])  # API route to add an IP to the whitelist, removing it from the graylist if present and adding it to the whitelist
@login_required
def whitelist_add():
    ip = request.json.get("ip") if request.json else None
    if not ip:
        return jsonify({"error": "missing IP"}), 400
    if not is_valid_ipv4(ip):
        return jsonify({"error": "invalid IP format"}), 400

    with lock:
        whitelist.add(ip)
        graylist.pop(ip, None)
        graylist_notified.discard(ip)
        current_whitelist = list(whitelist)
        current_graylist = ", ".join(graylist.keys()) if graylist else "-"
    if USE_TELEGRAM:
        send_telegram_message(f"✅ IP whitelisted: {ip}\nCurrent graylist: {current_graylist}\n\nNot you? Check immediately at http://{SERVER_IP}:{PORT}, change password and restart the service")
    
    return jsonify({"ok": True, "whitelist": current_whitelist})

@app.route("/api/whitelist/remove", methods=["POST"])  # API route to remove an IP from the whitelist
@login_required
def whitelist_remove():
    ip = request.json.get("ip") if request.json else None
    if not ip:
        return jsonify({"error": "missing IP"}), 400
    with lock:
        whitelist.discard(ip)
    return jsonify({"ok": True,})

@app.route("/api/watchlist")  # API route to get the current watchlist with the monitored IPs and their info (current/max values for each metric, etc.)
@login_required
def api_watchlist():
    with lock:
        return jsonify(watchlist)

@app.route("/api/watchlist/add", methods=["POST"])  # API route to add an IP to the watchlist
@login_required
def watchlist_add():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "missing IP"}), 400
    if not is_valid_ipv4(ip):
        return jsonify({"error": "invalid IP format"}), 400
    with lock:
        if ip not in watchlist:
            now = time.time()
            watchlist[ip] = {
                "ratio_current": 0,
                    "max_ratio": 0,
                    "entropy_current": 0,
                    "max_entropy": 0,
                    "std_current": None,
                    "min_std": None,
                    "pps_current": 0,
                    "max_pps": 0,
                    "first_seen": now,
                    "central_90_window": CAPTURE_DURATION,
                    "syn_count": 0,
                    "syn_count_rstsyn": 0,
                    "ack_count": 0,
                    "used_ports": [],
                    "mean_intervals": None,
                    "rst_count": 0,
                    "max_rst_ratio": 0,
                    "rst_ratio_current": 0,
                    "packet_count": 0,
                    "last_updated": {
                        "max_ratio": now,
                        "max_entropy": now,
                        "min_std": now,
                        "max_pps": now,
                        "max_rst_ratio": now
                    },
                }
    return jsonify({"ok": True})


@app.route("/api/watchlist/remove", methods=["POST"])  # API route to remove an IP from the watchlist
@login_required
def watchlist_remove():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error": "missing IP"}), 400
    with lock:
        watchlist.pop(ip, None)
    return jsonify({"ok": True})


# =================== START ===================

if __name__ == "__main__":
    print("\nStarting IDS monitoring...")
    print(f"- Interface: {IFACE} | Snapshot duration: {CAPTURE_DURATION}s")
    print(f"- See at http://{SERVER_IP}:{PORT}")
    print("\n[+] Loading persisted state...")

    initialize_db()  # initialize the database and tables if they don't exist

    # load persisted data
    ip_stats = restore_ip_stats(load_blob("ip_stats") or {})
    watchlist = load_blob("watchlist") or {}
    graylist = load_blob("graylist") or {}
    whitelist = set(load_blob("whitelist").keys())
    host_notes = load_blob("notes") or {}
    saved_config = load_blob("config") or {}
    if "THRESHOLDS" in saved_config:
        THRESHOLDS.update(saved_config["THRESHOLDS"])
    if "PENALTIES" in saved_config:
        PENALTIES.update(saved_config["PENALTIES"])

    time.sleep(2)  # small delay to ensure everything is loaded before starting the capture and analysis, adjust if needed

    print("[+] Persistence data loaded")
    print("[+] IDS monitoring started successfully.\n")

    threading.Thread(target=capture_and_analyze_loop, daemon=True).start()
    threading.Thread(target=persistence_loop, daemon=True).start()

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR) # only log errors

    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)

    print(f"\n[-] IDS monitoring stopped.\n")