# ids_server.py

# ================= IMPORTS =================

import os
import subprocess
import threading
import socket
import time

from config import *
from collections import defaultdict, deque, Counter
import statistics
import requests
import ipaddress
import math
import hashlib
import numpy as np
import math
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory, session, redirect, url_for, render_template, render_template_string
from flask_cors import CORS


# ================= CONFIG =================

# load thresholds and penalties from config.py
MIN_SYN_COUNT = THRESHOLDS["min_syn_count"]
SYN_ACK_RATIO_THRESHOLD = THRESHOLDS["synack_threshold"]
MAX_PORT_ENTROPY = THRESHOLDS["entropy_threshold"]
PPS_THRESHOLD = THRESHOLDS["pps_threshold"]

# define public routes that don't require authentication
PUBLIC_ROUTES = {"/login", "/favicon.ico"}

traffic = deque(maxlen=MAX_PACKETS_BUFFER) # deque of recent packets (rolling buffer)
stats_history = [] # list of timestamps, pps, unique_ips
ip_stats = defaultdict(lambda: { # stats for each IP, updated incrementally with each new packet, used for detection and watchlist monitoring
    "syn_count": 0,
    "ack_count": 0,
    "ports": deque(maxlen=200),
    "timestamps": deque(),
    "last_seen": 0,

    "max_pps": 0,
    "max_ratio": 0,
    "max_entropy": 0,
    "min_std": None
})
lock = threading.Lock() # lock to prevent race conditions

graylist = {} # list of IPs currently flagged as potential threats, with their info (score, reasons, etc.)
prev_graylist = {} # copy of the previous graylist to detect new flagged IPs for notifications
whitelist = set() # list of IPs to ignore (user-defined, e.g. trusted devices)
watchlist = {} # list of IPs to keep an eye on (user-defined, not necessarily malicious, but of interest), with their info (current/max of SYN/ACK ratio, entropy, pps, etc.)

observed_hosts = {} # list of hosts IPs, names and last seen
reset_times = {}  # IP -> timestamp of last reset (pardoning) to ignore packets from before the reset
ip_service_cache = {} # name cache for IP-based services
vendor_cache = {}  # name cache for MAC-based services
host_notes = {} # notes for hosts, keyed by MAC when valid, IP otherwise (manually set through the UI, used for display in the observed hosts list and for user annotations on specific devices or IPs)

# initialization of the app
app = Flask(__name__, static_folder="static")
CORS(app)

app.secret_key = os.urandom(32)  # needed for session management and signing cookies, we generate a random secret key each time the server starts, which means that sessions will be invalidated on each restart

# ================= UTILITIES =================

def sha256_hash(value):
    """get SHA256 of a string, used for auth username and password"""
    return hashlib.sha256(value.encode()).hexdigest()

def login_required(f):
    """decorator to protect routes that require authentication, checks if the user is logged in by looking at the session while checking for session timeout to automatically log out users after a period of inactivity"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return "Unauthorized", 401 # return 401 Unauthorized if not logged in

        if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
            session.clear()
            return "Session expired", 401 # return 401 Unauthorized if session has expired
        session["last_active"] = time.time()
        return f(*args, **kwargs)
    return decorated

def get_local_ip():
    """
    Utility function to get the local IP address of the server, used for messages to the Telegram bot if IP is not configured
    We use a common technique of connecting a UDP socket to a public IP (Google DNS) and getting the local socket name, which gives us the local IP address that would be used for outgoing connections
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

SERVER_IP = IP if IP else get_local_ip() # IP address of the server, used in messages to the Telegram bot, if not configured we get the local IP address automatically with the get_local_ip function

def send_telegram_message(message: str):
    """
    Sends a message to the configured Telegram chat using the bot token and chat ID, used for notifications when an IP is flagged as a potential threat.
    The message is sent as Markdown for better formatting, and we catch any exceptions to prevent the function from crashing if the Telegram API call fails (e.g. due to network issues or invalid configuration)
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=2)
    except Exception as e:
        print("Telegram notification failed:", e)

def apply_min_score_filter():
    """removes from graylist all IPs whose score is below the minimum threshold for alert"""
    to_remove = [ip for ip, info in graylist.items() if info.get("score", 0) < PENALTIES.get("Minimum score for alert", 5)]
    for ip in to_remove:
        del graylist[ip]


def is_private_ip(ip):
    """returns True if the IP is private (local network), False otherwise"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_ip_service(ip):
    """returns a name for the IP based on reverse DNS or external API, with caching"""
    now = time.time()
    # remove cache entries older than HOSTS_WINDOW_SECONDS
    to_remove = [i for i, v in ip_service_cache.items() if now - v["last_seen"] > HOSTS_WINDOW_SECONDS]
    for i in to_remove:
        del ip_service_cache[i]

    # update last_seen if in cache and return service name
    if ip in ip_service_cache:
        ip_service_cache[ip]["last_seen"] = now
        return ip_service_cache[ip]["service"]

    # try reverse DNS lookup first, if fails try external API, if that fails return "-"
    try:
        service = socket.gethostbyaddr(ip)[0]
    except Exception:
        try:
            res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
            service = res.json().get("org", "-") if res.status_code == 200 else "-"
        except Exception:
            service = "-"

    ip_service_cache[ip] = {"service": service, "last_seen": now}
    return service


def get_vendor(mac):
    """returns a vendor name for the given MAC address using an external API or caching. The cache is valid for HOSTS_WINDOW_SECONDS to avoid excessive API calls for frequently seen devices and unlimited memory growth."""
    now = time.time()
    # remove cache entries older than HOSTS_WINDOW_SECONDS
    if mac in vendor_cache and now - vendor_cache[mac]["last_seen"] < HOSTS_WINDOW_SECONDS:
        return vendor_cache[mac]["vendor"]

    # try to get vendor from external API, if fails return "Unknown"
    try:
        res = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        vendor = res.text.strip() if res.status_code == 200 else "Unknown"
    except Exception:
        vendor = "Unknown"

    # update cache with the new vendor and last seen time
    vendor_cache[mac] = {"vendor": vendor, "last_seen": now}
    return vendor


def entropy(ports):
    """calculates shannon entropy of a list of ports (used to detect port scans)"""
    if not ports:
        return 0

    counts = Counter(ports)
    total = sum(counts.values())

    E = 0
    for c in counts.values():
        p = c / total
        E -= p * math.log2(p)

    return E


def recalc_graylist_scores():
    """Recalculate scores and remove IPs below alert threshold."""
    with lock:
        min_score = PENALTIES["Minimum score for alert"]

        for ip, info in list(graylist.items()):
            reasons = info.get("reasons", [])

            # calculate score based on reasons and PENALTIES
            score = 0
            for r in reasons:
                if r in PENALTIES:
                    score += PENALTIES[r]
            info["score"] = score

            # remove if score is below minimum for alert
            if score < min_score:
                del graylist[ip]


# ================= CAPTURE AND ANALYZE =================

def analyze_traffic(new_packets):
    global graylist, prev_graylist

    new_ips = set(graylist.keys()) - set(prev_graylist.keys()) # detect new IPs that have been added to the graylist since the last analysis, so we can send notifications for them
    for ip in new_ips:
        info = graylist[ip]
        reasons = " / ".join(info["reasons"])
        if USE_TELEGRAM: # if Telegram integration is enabled, send a notification to the configured chat with the new flagged IP and its reasons, along with some additional info like the name of the service associated with the IP (if available) and links to external resources for further investigation
            msg = f"⚠️ NEW GRAYLISTED! ⚠️\n*{ip}* ({reasons})\n\nName: {get_ip_service(ip)}\nCheck at http://{SERVER_IP}:{PORT}\n\nMore info at:\n- https://ipinfo.io/{ip}\n- https://www.abuseipdb.com/check/{ip}"
            send_telegram_message(msg)

    # Load thresholds from config
    PPS_THRESHOLD = THRESHOLDS["pps_threshold"]
    SYN_ACK_RATIO_THRESHOLD = THRESHOLDS["synack_threshold"]
    MAX_PORT_ENTROPY = THRESHOLDS["entropy_threshold"]
    MIN_SYN_COUNT = THRESHOLDS["min_syn_count"]
    MAX_STD_INTERVALS = THRESHOLDS["max_std_timestamp"]

    now = time.time()

    for pkt in new_packets:
        ip = pkt.get("src_ip")
        if not ip or "." not in ip: # skip packets without valid IPs (sometimes tshark can output malformed IPs or empty fields, we skip those to avoid issues in the analysis)
            continue
        if ip in reset_times and pkt["ts"] < reset_times[ip]: # skip packets from before the last reset time for this IP, to avoid false positives from old activity before a reset/pardon action by the user
            continue

        s = ip_stats[ip]
        ts = pkt["ts"]
        s["timestamps"].append(ts)
        while s["timestamps"] and ts - s["timestamps"][0] > CAPTURE_DURATION: # remove timestamps that are outside of the capture window for the graylist detection, to keep the analysis focused on recent activity and prevent old packets from skewing the metrics
            s["timestamps"].popleft()

        # SYN/ACK flags
        if pkt.get("flags"):
            try:
                flags = int(pkt["flags"], 16)
                if flags & 0x02 and not (flags & 0x10): # pure SYN
                    s["syn_count"] += 1
                if flags & 0x10 and not (flags & 0x02): # pure ACK
                    s["ack_count"] += 1
            except:
                pass

        # Ports
        ports = pkt.get("ports", [])
        if len(ports) > 1: # we check both source and destination ports, but we only consider them if they are valid (numeric and below 49152, to exclude ephemeral ports that are legitimately used by clients and are not indicative of scanning activity, rather just normal temporary client behavior)
            port = int(ports[1])
            if port < 49152:
                s["ports"].append(port)

        s["last_seen"] = ts # update last seen time for this IP, used for graylist expiration and stats cleanup

    # Graylist update
    new_graylist = {}
    for ip, s in ip_stats.items():
        if not s["timestamps"] or len(s["timestamps"]) < 2: # we need at least 2 timestamps to calculate metrics like PPS and intervals, so we skip the graylist analysis for this IP until we have enough data points to work with, to avoid false positives from small samples and to give new IPs a chance to show their behavior before being flagged
            continue
        
        
        latest_ts = s["timestamps"][-1]
        recent_ts_arr = np.array([t for t in s["timestamps"] if latest_ts - t <= CAPTURE_DURATION]) # consider only timestamps within the capture duration for the graylist detection, converting it into a numpy array for easier calculations of percentiles

        if len(recent_ts_arr) >= 2:  # we need at least 2 timestamps in the recent window to calculate a meaningful PPS and to avoid false positives from small samples, if we have enough data points we can calculate a more accurate window based on the distribution of the timestamps using percentiles, otherwise we fallback to using the full CAPTURE_DURATION as the window for PPS calculation to give new IPs a chance to show their behavior before being flagged
            high_percentile = 95 # we use the 95th percentile to calculate the window for PPS calculation, to focus on the most recent activity and to avoid skewing the window with packets outside of the activity burst, this allows us to better capture bursts of activity that can be regular traffic. If otherwise the 95th percentile window is large compared to CAPTURE_DURATION, we know it's a sustained activity and a potential flood attack
            start_ts = np.percentile(recent_ts_arr, 100 - high_percentile)
            end_ts = np.percentile(recent_ts_arr, high_percentile)
            window = end_ts - start_ts
        else:
            # fallback: uses CAPTURE_DURATION as default time window
            window = CAPTURE_DURATION

        # calculate metrics for this IP based on the recent timestamps and stats
        # if the window is too small (e.g. < 2.5s, we treat it as a regular traffic burst, typical of web browsing or normal client behavior, and we calculate PPS based on the full CAPTURE_DURATION, otherwise we calculate PPS based on the actual window of activity to better capture potential flood attacks that are sustained over time)
        pps = len(recent_ts_arr) / window if window > 2.5 else len(recent_ts_arr) / CAPTURE_DURATION
        ratio = s["syn_count"] / max(1, s["ack_count"]) # calculate SYN/ACK ratio, avoiding division by zero
        entropy_val = entropy(list(s["ports"])) # calculate entropy of destination ports

        # Std intervals
        std_val = None
        intervals = [t2 - t1 for t1, t2 in zip(recent_ts_arr, recent_ts_arr[1:])]
        if len(intervals) > 1: # calculate standard deviation of intervals between packets, but only if we have enough intervals to get a meaningful value, this can help us detect regular patterns in the traffic that are indicative of automated tools or bots, while allowing for some variability in the timing of the packets to avoid false positives from perfectly regular traffic bursts that can occur in normal client behavior
            std_val = statistics.stdev(intervals)

        # initialize the max/current values for each metric if not already set, we use setdefault to only set the default values when they are not already set, this allows us to keep the previous max values for each metric and only update them when we see a new "worse" value for that metric, while also keeping track of the current value for display purposes in the UI and for monitoring the evolution of the IP's behavior over time
        s.setdefault("max_pps", 0)
        s.setdefault("max_ratio", 0)
        s.setdefault("max_entropy", 0)
        s.setdefault("min_std", None)
        s.setdefault("last_updated", {
            "max_pps": now,
            "max_ratio": now,
            "max_entropy": now,
            "min_std": now
        })

        # we also set default values for: 95th percentile time window, packet/SYN/ACK counts, used ports and mean intervals, which are used for display purposes in the UI and can provide additional context on the behavior of the IP when it is flagged as a potential threat
        s.setdefault("p95_window", CAPTURE_DURATION)
        s.setdefault("packet_count", 0)
        s.setdefault("syn_count", 0)
        s.setdefault("ack_count", 0)
        s.setdefault("used_ports", [])
        s.setdefault("mean_intervals", None)        

        # Update metrics only if they are "worse"

        # PPS
        if pps > s.get("max_pps", 0):
            s["max_pps"] = round(pps, 1)
            s["last_updated"]["max_pps"] = now
            if len(recent_ts_arr) >= 10: # we calculate the 95th percentile time window only if we have enough data points to get a meaningful value, otherwise we fallback to using the full CAPTURE_DURATION as the window for display purposes in the UI, this allows us to better capture bursts of activity that can be regular traffic while avoiding false positives from small samples
                p95_window = np.percentile(recent_ts_arr, high_percentile) - np.percentile(recent_ts_arr, 100 - high_percentile)
            else:
                p95_window = CAPTURE_DURATION
            s["p95_window"] = round(p95_window, 3)
            s["packet_count"] = len(recent_ts_arr)

        # SYN/ACK ratio
        if ratio > s.get("max_ratio", 0):
            s["max_ratio"] = round(ratio, 2)
            s["last_updated"]["max_ratio"] = now
        
        # Entropy
        if entropy_val > s.get("max_entropy", 0):
            s["max_entropy"] = round(entropy_val, 2)
            s["last_updated"]["max_entropy"] = now
            s["used_ports"] = list(dict.fromkeys(sorted(s["ports"], key=s["ports"].count, reverse=True))) if s["ports"] else [] # orders the used ports by frequency and removes duplicates

        # Std of intervals
        if std_val is not None and (s.get("min_std") is None or std_val < s["min_std"]):
            s["min_std"] = round(std_val, 4)
            s["last_updated"]["min_std"] = now
            s["mean_intervals"] = round(statistics.mean(intervals), 4) if intervals else None

        # REASONS AND SCORE
        reasons = []
        if s["max_pps"] >= PPS_THRESHOLD:
            reasons.append("Packet flood")
        if s["syn_count"] >= MIN_SYN_COUNT and s["max_ratio"] >= SYN_ACK_RATIO_THRESHOLD: # only if we have at least a minimum number of SYN packets
            reasons.append("SYN flood")
        if s["max_entropy"] >= MAX_PORT_ENTROPY:
            reasons.append("Port scan")
        if s.get("min_std") and s["min_std"] < MAX_STD_INTERVALS:
            reasons.append("Regular intervals")

        score = sum(PENALTIES[r] for r in reasons if r in PENALTIES)

        if score >= PENALTIES.get("Minimum score for alert", 5) and ip not in whitelist and "," not in ip: # only add to graylist if score is above minimum for alert, IP is not in whitelist and is not malformed (sometimes tshark can output multiple IPs separated by commas for some packets, we skip those to avoid issues in the analysis)
            new_graylist[ip] = { # we store the reasons and score for each IP in the graylist, along with the current and max values for each metric, and some additional info likeS last updated time for each metric, which can be used for display purposes in the UI and to monitor the evolution of the IP's behavior over time
                "score": score,
                "reasons": reasons,
                "ratio": round(s["max_ratio"], 2),
                "entropy": round(s["max_entropy"], 2),
                "max_pps": round(s["max_pps"], 1),
                "std_intervals": round(s["min_std"], 4) if s.get("min_std") else None,
                "last_updated": s["last_updated"],
                "p95_window": s["p95_window"],
                "syn_count": s["syn_count"],
                "ack_count": s["ack_count"],
                "used_ports": s["used_ports"],
                "mean_intervals": s["mean_intervals"],
                "packet_count": s["packet_count"]
            }

    prev_graylist = graylist.copy() # update the previous graylist with the current one for the next analysis cycle, this allows us to detect new IPs that are added to the graylist in the next cycle and send notifications for them, while keeping track of the existing flagged IPs and their evolution over time without sending duplicate notifications for them
    graylist = new_graylist # update the graylist with the new one after the analysis
    apply_min_score_filter() # apply the minimum score filter to remove any IPs that are below the threshold for alert

    # WATCHLIST UPDATE

    for ip in watchlist: # update the watchlist metrics for each IP in the watchlist based on the latest stats, so that the user can monitor their activity and see how close they are to the thresholds. We only update the watchlist metrics for IPs that are still in the ip_stats (i.e. have recent activity), otherwise we keep their last known metrics until they have new activity or are removed from the watchlist by the user.
        if ip not in ip_stats: # skip the update and keep the last known metrics if we don't have stats for this IP 
            continue

        s = ip_stats[ip] # get the stats for this IP, we know it exists because we checked before, and it's updated with the latest activity from the new packets
        w = watchlist[ip] # get the watchlist entry for this IP, we know it exists because we are iterating over the watchlist
        

        if len(s["timestamps"]) < 2: # if we don't have at least 2 timestamps, we can't calculate a meaningful PPS or intervals, so we skip the update for this IP to avoid false positives from small samples, and we keep the last known metrics until we have enough data points to update again
            continue
        
        window = s["timestamps"][-1] - s["timestamps"][0]
        if window > 1.00: # calculate PPS only if we have a reasonable window (1 sec) to avoid false positives from regular bursts in traffic
            pps = len(s["timestamps"]) / max(window, 1e-6)
        else:
            pps = 0

        ratio = s["syn_count"] / max(1, s["ack_count"]) # SYN/ACK ratio, same logic as before for the graylist detection
        entropy_val = entropy(list(s["ports"])) # entropy of destination ports, same logic as before for the graylist detection

        std_val = None
        intervals = []
        prev = None
        if len(s["timestamps"]) > 10: # calculate std of intervals only if we have enough data points to avoid false positives from small samples, same logic as before for the graylist detection
            for t in s["timestamps"]:
                if prev is not None:
                    intervals.append(t - prev)
                prev = t
            if len(intervals) > 1:
                std_val = statistics.stdev(intervals)

        now = time.time()


        # initialize first_seen for this IP if not already set, used to track how long an IP has been active and for display purposes in the UI, so we can show when an IP was first seen in the traffic and how it evolves over time with its metrics and potential flagging as a threat. We set it to the current time when we first see this IP in the stats, and we don't update it afterwards to keep the original first seen time.
        if "first_seen" not in w:
            w["first_seen"] = now

        # initialize last_updated for each metric to track when each metric was last updated for this IP, used for display purposes in the UI to show when each metric was last updated
        if "last_updated" not in w:
            w["last_updated"] = {"max_ratio": now, "max_entropy": now, "min_std": now, "max_pps": now} # default to now
        
        # Update watchlist metrics only if they are "worse" than the current ones, we use the same logic as before for the graylist detection to only update the max values for each metric when we see a new "worse" value, while also keeping track of the current value for display purposes in the UI and for monitoring the evolution of the IP's behavior over time in the watchlist

        # PPS
        if pps > w["max_pps"]:
            w["max_pps"] = round(pps, 1)
            w["last_updated"]["max_pps"] = now
            w["p95_window"] = s.get("p95_window", CAPTURE_DURATION)
            w["packet_count"] = len(s["timestamps"])
        w["pps_current"] = round(pps, 1)

        # Ratio
        if ratio > w["max_ratio"]:
            w["max_ratio"] = round(ratio, 2)
            w["last_updated"]["max_ratio"] = now
            w["syn_count"] = s["syn_count"]
            w["ack_count"] = s["ack_count"]
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

    # Cleanup of ip_stats to remove IPs that haven't been seen in the last HOSTS_WINDOW_SECONDS, to prevent unneccessary memory growth from old IPs that are no longer active
    to_delete = [
        ip for ip, s in ip_stats.items()
        if now - s["last_seen"] > HOSTS_WINDOW_SECONDS
    ]
    for ip in to_delete:
        del ip_stats[ip]


def capture_and_analyze_loop():
    """
    Main loop to capture traffic with tshark, parse it, update the shared traffic list and observed hosts, and call the analyze_traffic function to update the graylist, watchlist and stats.
    This runs in a separate thread to not block the Flask server.
    """
    global traffic, stats_history

    while True:
        # command to execute
        cmd = [
            "tshark",
            "-l",
            "-i", IFACE, # interface on which to capture packets on
            "-a", f"duration:{CAPTURE_DURATION}", # time duration of the capture
            "-T", "fields", 
            "-e", "frame.time_epoch", # timestamp
            "-e", "frame.len", # packet lenght
            "-e", "eth.src", # source MAC
            "-e", "eth.dst", # destination MAC
            "-e", "ip.src", # source IP
            "-e", "ip.dst", # destination IP
            "-e", "tcp.flags", # TCP flags (e.g. SYN, ACK...)
            "-e", "tcp.srcport", # TCP source port
            "-e", "tcp.dstport", # TCP destination PORT
            "-e", "udp.srcport", # UDP source PORT
            "-e", "udp.dstport", # UDP destination PORT
            "-E", "separator=|",
            "-Y", 'ip.version == 4 and not ip.addr == 127.0.0.1' # IPv4 only and not from localhost
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=CAPTURE_DURATION + 5 # +5s to give extra buffer time
            )
        except Exception as e:
            print(f"tshark ERROR: {e}")
            continue

        if proc.returncode != 0:
            print("tshark failed →", proc.stderr.strip())
            continue

        print(f"tshark → {len(proc.stdout.splitlines())} rows recieved")

        # parse output and update traffic list
        new_packets = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) < 9: # we need at least 9 fields (timestamp, length, src MAC, dst MAC, src IP, dst IP, flags, src port, dst port) to have a meaningful packet entry, if we don't have enough fields it means the packet is malformed or missing important info, so we skip it to avoid issues in the analysis and to keep the traffic data clean and consistent
                continue

            # validate and convert timestamp and length, skip if invalid
            try:
                ts = float(parts[0])
            except ValueError:
                continue

            # append the new packet
            new_packets.append({
                "ts": ts,
                "src_ip": parts[4],
                "dst_ip": parts[5],
                "src_mac": parts[2],
                "dst_mac": parts[3],
                "flags": parts[6],
                "ports": [p for p in parts[7:11] if p.isdigit()]
            })


        # update shared data structures with lock
        with lock:
            traffic.extend(new_packets) # auto-trims old packets if we exceed MAX_PACKETS_BUFFER because it's a deque with maxlen

            # update observed hosts with the new packets
            now = time.time()
            for pkt in new_packets:
                mac = pkt.get("src_mac")
                ip = pkt.get("src_ip")
                if not mac or not ip:
                    continue  # skip packets without valid MAC or IP
                if ip in ("127.0.0.1") or "," in ip: # skip localhost and malformed IPs (sometimes tshark can output multiple IPs separated by commas for some packets, we skip those to avoid issues in the analysis)
                    continue

                if is_private_ip(ip):
                    # LOCAL host → name based on MAC address
                    if not mac:
                        mac = "-"
                        vendor = "-"
                    else:
                        vendor = get_vendor(mac)
                else:
                    # EXTERNAL host → name based on IP address
                    mac = "-"
                    vendor = get_ip_service(ip)

                # we check if there's already an observed host with the same MAC address, because we want to keep the same identity for a device even if its IP changes (e.g. DHCP), so we look for an existing entry with the same MAC and update it instead of creating a new one, to maintain continuity in tracking devices based on their MAC address as their identity, while allowing their IP to change over time without losing the connection to the same device in the observed hosts list
                existing_key = None
                for key in observed_hosts.keys():
                    existing_mac = key.split("_")[0]
                    if existing_mac == mac and mac != "-": # we also check that the MAC is not "-" because that means we don't have a valid MAC for this host and we don't want to mix different hosts with invalid MACs together
                        existing_key = key
                        break

                # if there's an existing host with the same MAC but a different IP, we have a conflict because we don't want to update the existing host with a new IP if that IP is already associated with another MAC address (which can happen in cases of IP spoofing or misconfigured devices), so we check for this conflict and if we find it, we skip updating this packet to avoid mixing identities and creating inaccurate entries in the observed hosts list
                ip_conflict = False
                for key, info in observed_hosts.items():
                    existing_mac = key.split("_")[0]
                    if info["last_ip"] == ip and existing_mac != mac:
                        ip_conflict = True
                        break

                if ip_conflict: # don't add new host if the IP is already associated with a different MAC address
                    continue
                    
                # if we have an existing host with the same MAC, we update its IP, last seen time and vendor
                if existing_key:
                    observed_hosts[existing_key]["last_ip"] = ip
                    observed_hosts[existing_key]["last_seen"] = now
                    observed_hosts[existing_key]["name"] = vendor

                    new_key = f"{mac}_{ip}"
                    if new_key != existing_key: # changes the key to include updated MAC and IP
                        observed_hosts[new_key] = observed_hosts.pop(existing_key)

                # if there's no type of conflict, simply add a new host
                else:
                    observed_hosts[f"{mac}_{ip}"] = {
                        "last_ip": ip,
                        "last_seen": now,
                        "name": vendor
                    }


            # remove hosts not seen in the last HOSTS_WINDOW_SECONDS
            for mac in list(observed_hosts.keys()):
                if now - observed_hosts[mac]["last_seen"] > HOSTS_WINDOW_SECONDS:
                    del observed_hosts[mac]

            analyze_traffic(new_packets) # analyze the traffic and update graylist, watchlist and stats

            # get the snapshot of current stats for overview chart
            this_snapshot = {
                "ts": int(time.time()),
                "packets": len(new_packets),
                "pps": round(len(new_packets) / CAPTURE_DURATION, 1),
                "unique_ips": len({p["src_ip"] for p in traffic if p["src_ip"]})
            }
            stats_history.append(this_snapshot)
            stats_history[:] = stats_history[-STATS_KEEP:] # keep only recent stats in memory

        time.sleep(0.3) # small delay before next capture to prevent high stress on the CPU, adjust if needed


# =================== ROUTES ===================

@app.before_request # before each request, check if the route is public or if the user is logged in. If the user is not logged in and tries to access a protected route, redirect to login. If the session has expired, clear the session and return a 401 Unauthorized response. Otherwise, update the last active time in the session to keep it alive.
def require_login():
    path = request.path
    # if the path is not in the list of public routes, we require the user to be logged in to access it
    if not any(path.startswith(r) for r in PUBLIC_ROUTES):
        if not session.get("logged_in"):
            return redirect("/login")
        # check for session timeout
        if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
            session.clear()
            return redirect("/login")
        session["last_active"] = time.time()


@app.route("/") # home route, serves the main page of the UI
@login_required
def index():
    return send_from_directory("static", "index.html")

@app.route("/login", methods=["GET", "POST"]) # login route: if GET, serve the login page, if POST, check the credentials and if correct, set the session as logged in and redirect to home, otherwise show an error message. The credentials are hashed with SHA256 and compared to the hashed values in the config for better security (so we don't store plaintext passwords in the code), and we use a simple form with username and password fields for the login page.
def login():
    error = ""
    if request.method == "POST":
        # get the username and password from the form, hash them with SHA256 and compare to the hashed values in the config, if they match, set the session as logged in and redirect to home, otherwise show an error message
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if sha256_hash(username) == IDS_USERNAME and sha256_hash(password) == IDS_PASSWORD:
            session["logged_in"] = True
            session["last_active"] = time.time()
            return redirect("/")
        else:
            error = "Username or password incorrect"
    
    # if GET request, render the login page with the error message (if any)
    return render_template_string("""
    <html>
    <head>
        <title>Login IDS</title>
        <link rel="icon" href="/favicon.ico" type="image/x-icon">
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                height: 100vh;
                justify-content: center;
                align-items: center;
                background: #f0f2f5;
            }
            .login-box {
                background: #fff;
                padding: 20px 30px;
                border-radius: 8px;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            }
            input[type=text], input[type=password] {
                width: 100%;
                padding: 10px;
                margin: 5px 0 15px 0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            input[type=submit] {
                width: 100%;
                padding: 10px;
                background: #007bff;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            .error {
                color: red;
                margin-bottom: 10px;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Login IDS</h2>
            <form method="post">
                <div class="error">{{ error }}</div>
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="submit" value="Login">
            </form>
        </div>
    </body>
    </html>
    """, error=error)
    
@app.route("/logout", methods=["POST"]) # logout route to clear the session and log the user out
@login_required
def logout():
    session.clear() # clear the session to log the user out
    return jsonify({"ok": True})

    
@app.route("/api/config") # API route to get the current configuration values (thresholds, penalties, capture settings, etc.) for display in the UI and use in the frontend logic
@login_required
def get_config():
    return jsonify({
        "THRESHOLDS": THRESHOLDS,
        "PENALTIES": PENALTIES,
        "IFACE": IFACE,
        "PORT": PORT,
        "CAPTURE_DURATION": CAPTURE_DURATION,
        "MAX_PACKETS_BUFFER": MAX_PACKETS_BUFFER,
        "STATS_KEEP": STATS_KEEP,
        "RECENT_HISTORY_TIMEFRAME": RECENT_HISTORY_TIMEFRAME,
        "HOSTS_WINDOW_SECONDS": HOSTS_WINDOW_SECONDS
    })

@app.route('/api/hosts/note', methods=['POST']) # API route to save a note for a host, identified by either its MAC or IP address. The note is stored in the host_notes dictionary and can be used to add custom comments or observations about specific hosts in the UI, which can be helpful for tracking and investigation purposes
@login_required
def save_host_note():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip()
    ip = data.get("ip", "").strip()
    note = data.get("note", "").strip()

    with lock:
        if mac != "" and mac != "-": # use MAC keying if valid and not "-" (not local)
            host_notes[mac] = note
        elif ip != "" and ip != "-": # else use IP keying if valid and not "-"
            host_notes[ip] = note
        else:
            return jsonify({"error": "missing identifier"}), 400

    return jsonify({"success": True})

@app.route("/favicon.ico") # route to serve the favicon (prevent 404 errors in the console)
def favicon():
    return send_from_directory("static", "favicon.ico")

@app.route("/api/hosts") # API route to get the list of observed hosts with their info (IP, MAC, name, status), used to populate the hosts overview table in the UI. Only includes hosts seen in the last HOSTS_WINDOW_SECONDS to avoid showing stale data.
@login_required
def api_hosts():
    now = time.time()
    hosts = []

    with lock:
        for key, info in observed_hosts.items():
            if now - info["last_seen"] > HOSTS_WINDOW_SECONDS: # skip hosts that haven't been seen in the last HOSTS_WINDOW_SECONDS to avoid showing stale data in the UI
                continue

            ip = info["last_ip"]
            mac = key.split("_")[0]
            name = info.get("name", "-")

            last_seen = info["last_seen"]
            score = graylist.get(ip, {}).get("score", 0)

            note = host_notes.get(mac, host_notes.get(ip, ""))

            hosts.append({
                "mac": mac,
                "name": name,
                "last_ip": ip,
                "last_seen": last_seen,
                "score": score,
                "note": note
            })

    return jsonify(hosts)

@app.route("/api/stats") # API route to get the historical stats for the overview charts in the UI (packets per second, unique IPs, etc.) and the top sources in the recent history (last RECENT_HISTORY_TIMEFRAME) to show in the stats overview section of the UI.
@login_required
def api_stats():
    with lock:
        now = time.time()

        top_sources = Counter( # get the most common source IPs in the recent history (last RECENT_HISTORY_TIMEFRAME)
            p["src_ip"]
            for p in traffic
            if p["src_ip"]
            and "." in p["src_ip"]
            and now - p["ts"] <= RECENT_HISTORY_TIMEFRAME
        ).most_common(12)

        return jsonify({
            "stats": stats_history,
            "top_sources": top_sources
        })


@app.route("/api/thresholds", methods=["GET"]) # API route to get the current metric thresholds for anomaly detection
@login_required
def get_thresholds():
    return jsonify(THRESHOLDS)

@app.route("/api/thresholds", methods=["POST"]) # API route to update the current metric thresholds for anomaly detection
@login_required
def update_thresholds():
    data = request.json or {} # use empty dict if no data to avoid errors
    for key in THRESHOLDS:
        if key in data:
            try:
                THRESHOLDS[key] = float(data[key]) # update the threshold with the new value
            except ValueError:
                pass # if conversion fails keep the old value
    return jsonify(THRESHOLDS)


@app.route("/api/penalties", methods=["GET"]) # API route to get the current penalties for each motivation
@login_required
def get_penalties():
    return jsonify(PENALTIES)

@app.route("/api/penalties", methods=["POST"]) # API route to update the current penalties for each motivation
@login_required
def update_penalties():
    global PENALTIES
    data = request.json or {}
    updated = False

    for key in data:
        try:
            PENALTIES[key] = float(data[key]) # update the penalty with the new value
            updated = True
        except ValueError:
            pass

    if updated:
        apply_min_score_filter()  # clears the graylist of IPs that are now below the minimum score for alert after the penalties update

    return jsonify(PENALTIES)


@app.route("/api/graylist") # API route to get the current graylist with the flagged IPs and their info (score, reasons, metrics values...)
@login_required
def api_graylist():
    with lock:
        return jsonify(graylist)

@app.route("/api/reset", methods=["POST"]) # API route to reset an IP, allowing the user to pardon an IP and remove it from the graylist, resetting its stats and giving it a clean slate
@login_required
def graylist_reset():
    with lock:
        ip = request.json.get("ip") # get the IP to reset from the request body, expected to be a JSON object with an "ip" field containing the IP address to reset
        if ip:
            now = time.time()
            reset_times[ip] = now

            graylist.pop(ip, None) # remove the IP from the graylist if it's there,

            if ip in ip_stats: # reset the stats for this IP (general and watchlist)
                s = ip_stats[ip]
                s["max_ratio"] = 0
                s["max_entropy"] = 0
                s["max_pps"] = 0
                s["mean_intervals"] = None
                s["last_updated"] = {
                    "max_ratio": now,
                    "max_entropy": now,
                    "max_pps": now,
                    "min_std": now
                }
                s["pps_current"] = 0
                s["ratio_current"] = 0
                s["entropy_current"] = 0
                s["std_current"] = None
                s["used_ports"] = []
                s["mean_intervals"] = None
                s["syn_count"] = 0
                s["ack_count"] = 0
                s["p95_window"] = CAPTURE_DURATION
                s["packet_count"] = 0
                
                
                if ip in watchlist: # also reset the watchlist info for this IP if it's in the watchlist, so that if the user has it in the watchlist to monitor it, they will see the reset metrics and can monitor it again from a clean slate after the reset
                    w = watchlist[ip]
                    w["max_ratio"] = 0
                    w["max_entropy"] = 0
                    w["max_pps"] = 0
                    w["min_std"] = None
                    w["last_updated"] = {
                        "max_ratio": now,
                        "max_entropy": now,
                        "max_pps": now,
                        "min_std": now
                    }
                    w["pps_current"] = 0
                    w["ratio_current"] = 0
                    w["entropy_current"] = 0
                    w["std_current"] = None
                    w["used_ports"] = []
                    w["mean_intervals"] = None
                    w["syn_count"] = 0
                    w["ack_count"] = 0
                    w["p95_window"] = CAPTURE_DURATION
                    w["packet_count"] = 0

            to_remove = [k for k, t in reset_times.items() if now - t > HOSTS_WINDOW_SECONDS] # cleanup old reset times to prevent memory growth
            for k in to_remove:
                del reset_times[k]

        return jsonify({"ok": True})


@app.route("/api/whitelist") # API route to get the current whitelist
@login_required
def api_whitelist():
    with lock:
        return jsonify(list(whitelist))

@app.route("/api/whitelist/add", methods=["POST"]) # API route to add an IP to the whitelist, removing it from the graylist if present and adding it to the whitelist so that it's ignored in future analyses
@login_required
def whitelist_add():
    ip = request.json.get("ip")
    if ip:
        whitelist.add(ip)
        graylist.pop(ip, None)
    return jsonify({"ok": True, "whitelist": list(whitelist)})

@app.route("/api/whitelist/remove", methods=["POST"]) # API route to remove an IP from the whitelist, allowing it to be analyzed again and potentially added to the graylist if it exceeds the thresholds
@login_required
def whitelist_remove():
    ip = request.json.get("ip")
    whitelist.discard(ip)
    return jsonify({"ok": True, "whitelist": list(whitelist)})


@app.route("/api/watchlist") # API route to get the current watchlist with the monitored IPs and their info (current/max values for each metric, etc.)
@login_required
def api_watchlist():
    return jsonify(watchlist)

@app.route("/api/watchlist/add", methods=["POST"]) # API route to add an IP to the watchlist, allowing the user to monitor its activity and see current/max metrics
@login_required
def watchlist_add():
    ip = request.json.get("ip")
    if ip and ip not in watchlist: # only add to watchlist if we have a new IP and it's not already in the watchlist
        now = time.time()
        watchlist[ip] = { # initialize the watchlist info for this IP with default values, we will update these values in the analyze_traffic function as we see new activity from this IP
            "ratio_current": 0,
            "max_ratio": 0,
            "entropy_current": 0,
            "max_entropy": 0,
            "std_current": None,
            "min_std": None,
            "pps_current": 0,
            "max_pps": 0,
            "first_seen": now,
            "p95_window": CAPTURE_DURATION,
            "syn_count": 0,
            "ack_count": 0,
            "used_ports": [],
            "mean_intervals": None,
            "packet_count": 0,
            "last_updated": {
                "max_ratio": now,
                "max_entropy": now,
                "min_std": now,
                "max_pps": now
            }
        }
    return jsonify({"ok": True})

@app.route("/api/watchlist/remove", methods=["POST"]) # API route to remove an IP from the watchlist, stopping the monitoring of its activity and removing it from the watchlist
@login_required
def watchlist_remove():
    ip = request.json.get("ip")
    if ip:
        watchlist.pop(ip, None)
    return jsonify({"ok": True})


# =================== START ===================

if __name__ == "__main__": # main entry point of the program, starts the capture and analysis loop in a separate thread and then starts the Flask server to serve the UI and API routes
    print("Starting IDS monitoring...")
    print(f"Interface: {IFACE} | Snapshot duration: {CAPTURE_DURATION}s")
    print(f"Open on port {PORT}\n")

    
    # start the capture and analyze loop in a separate thread to not block the Flask server, set as daemon so it will automatically close when the main program exits
    threading.Thread(target=capture_and_analyze_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, debug=False)