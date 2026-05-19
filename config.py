# config.py

from os import getenv
from pathlib import Path
from dotenv import load_dotenv


# thresholds for anomaly detection
THRESHOLDS = {
    "min_syn_count": 10,  # minimum number of SYN packets to even consider an IP as a potential attacker
    "min_rst_count": 10,  # minimum number of RST packets to even consider an IP as a potential attacker (used for unauthorized access detection)
    "synack_threshold": 5,  # minimum ratio of SYN to ACK packets to consider an IP as an attacker
    "entropy_threshold": 3.3,  # minimum entropy of destination ports to consider an IP as performing a port scan
    "pps_threshold": 200,  # minimum packets per second to consider an IP as performing a packet flood (e.g. DoS)
    "max_std_timestamp": 0.05,  # maximum standard deviation of packet timestamps to consider an IP as sending packets at regular intervals
    "rstsyn_ratio": 0.5  # minimum ratio of RST-ended to SYN-tried connections to consider an IP as performing connection probing (used for unauthorized access detection)
}

# Penalties for each motivation (used to calculate the overall score of an IP, pure values)
PENALTIES = {
    "Packet flood": 4,
    "SYN flood": 4,
    "Port scan": 3,
    "Regular intervals": 2,
    "Connection probing": 4,
    "Minimum score for alert": 5,  # minimum score to reach before an IP is considered an attacker and reported in the alerts
}

load_dotenv() # load .env variables

IFACE = getenv("IFACE", "wlan0")
PORT = int(getenv("PORT", 8080))
IP = getenv("IP", None) if getenv("IP", None) != "None" else None

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

CAPTURE_DURATION = 5  # dump time (in seconds)
RECENT_HISTORY_TIMEFRAME = 60  # recent history time threshold (in seconds, used for checking suspicious activity)
MAX_PACKETS_BUFFER = 25000  # max packets to store in memory in each dump
GRAPH_HISTORY = 300  # max time history on overview charts (in seconds)
HOSTS_WINDOW_SECONDS = 86400  # max time history on observed hosts (in seconds)
SESSION_TIMEOUT = 3600  # time (in seconds) after which we consider a session expired if no activity is observed from that IP
EPHEMERAL_PORT_THRESHOLD = 49152 # Avoid considering ephemeral ports in the analysis, as they are commonly used for legitimate outgoing connections.
# In practice, even lower ports (e.g. starting from 30'000) are commonly used as ephemeral, but we set the threshold at 49152 as IANA standard. Change if needed

USE_TELEGRAM = getenv("USE_TELEGRAM", "False").lower() in ("true", "1", "yes")
TELEGRAM_TOKEN = getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = getenv("TELEGRAM_CHAT_ID")
IDS_USERNAME = getenv("IDS_USERNAME_HASH").strip()
IDS_PASSWORD = getenv("IDS_PASSWORD_HASH").strip()

if USE_TELEGRAM and (not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID):
    raise ValueError("Telegram is used but TOKEN or CHAT_ID are missing!")