# config.py

from os import getenv
from dotenv import load_dotenv


# Treshholds for anomaly detection
THRESHOLDS = {
    "min_syn_count": 5, # minimum number of SYN packets to even consider an IP as a potential attacker
    "synack_threshold": 3, # minimum ratio of SYN to ACK packets to consider an IP as an attacker
    "entropy_threshold": 2.3, # minimum entropy of destination ports to consider an IP as performing a port scan
    "pps_threshold": 100, # minimum packets per second to consider an IP as performing a packet flood
    "max_std_timestamp": 0.05 # maximum standard deviation of packet timestamps to consider an IP as sending packets at regular intervals
}

# Penalties for each motivation (used to calculate the overall score of an IP, pure values)
PENALTIES = {
    "Packet flood": 5,
    "SYN flood": 3,
    "Port scan": 3,
    "Regular intervals": 2,
    "Minimum score for alert": 5 # minimum score to reach before an IP is considered an attacker and reported in the alerts
}

IFACE = "wlan0"     # tshark Interface on which to listen on (default "wlan0")
PORT = 8080     # port for the web serveru
IP = "100.87.3.45"   # IP address of the server to (specify, else it will be taken the local IP of the machine)
CAPTURE_DURATION = 5    # dump time (in seconds)
MAX_PACKETS_BUFFER = 5000   # max packets to store in memory in each dump
STATS_KEEP = 300    # max time history on overview charts (in seconds)
RECENT_HISTORY_TIMEFRAME = 60 # recent history time threshold (in seconds)
HOSTS_WINDOW_SECONDS = 86400    # max time history on observed hosts (in seconds)
SESSION_TIMEOUT = 3600  # time (in seconds) after which we consider a session expired if no activity is observed from that IP

load_dotenv()  # load environment variables from .env file and define configuration variables for Telegram integration and IDS credentials
USE_TELEGRAM = getenv("USE_TELEGRAM", "False").lower() in ("1","true","yes")
TELEGRAM_TOKEN = getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = getenv("TELEGRAM_CHAT_ID")
IDS_USERNAME = getenv("IDS_USERNAME_HASH").strip()
IDS_PASSWORD = getenv("IDS_PASSWORD_HASH").strip()

if USE_TELEGRAM and (not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID):
    raise ValueError("Telegram is used but TOKEN or CHAT_ID are missing!")