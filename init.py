# init.py

import os
import bcrypt
from hashlib import sha256
import getpass

ENV_FILE = ".env" 


def hash_value(value: str) -> str:
    """Salt hash a string using bcrypt and SHA256 pre-hashing (used for IDS credentials)"""
    return bcrypt.hashpw(sha256(value.encode("utf-8")).hexdigest().encode(), bcrypt.gensalt()).decode("utf-8") # pre hashing with SHA256 to avoid bcrypt's 72 bytes limit


def ask_bool(prompt: str, default: bool = False) -> bool:
    """wrapper to ask a yes/no question with default and basic validation"""
    val = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if val == "":
        return default
    return val in ["y", "yes", "true", "1"]


print("\n=== IDS .env initializer ===\n")

if os.path.exists(ENV_FILE): # overwrite protection
    overwrite = ask_bool(".env already exists. Overwrite?", False)
    if not overwrite:
        print("Aborted.")
        exit(0)

# TELEGRAM NOTIFICATIONS SETUP
use_telegram = ask_bool("Enable Telegram alerts?", False)
telegram_token = ""
telegram_chat_id = ""
if use_telegram:
    telegram_token = input("Telegram BOT token: ").strip()
    telegram_chat_id = input("Telegram CHAT ID: ").strip()

# CREDENTIALS SETUP
print("\n--- Authentication setup ---")
username = input("IDS username: ").strip()
password = getpass.getpass("IDS password: ").strip()

username_hash = hash_value(username)
password_hash = hash_value(password)

# CONFIG SETUP
print("\n--- IDS configuration variables ---")

iface = input("Interface to listen on (e.g. wlan0, eth0, ... - default 'wlan0'): ").strip()
if iface == "":
    iface = "wlan0"

port_input = input("Web server port (default 8080): ").strip()
try:
    port = int(port_input)
except ValueError:
    if port_input == "":
        port = 8080
    else:
        print("Invalid port, using default 8080")
        port = 8080

ip = input("Server IP (IPv4, e.g. 1.1.1.1) (optional, leave empty for auto): ").strip()
if ip == "":
    ip = None

### GENERATE .env CONTENT AND CONFIRM

env_content = f"USE_TELEGRAM={str(use_telegram)}\nTELEGRAM_TOKEN={telegram_token if telegram_token != '' else 'None'}\nTELEGRAM_CHAT_ID={telegram_chat_id if telegram_chat_id != '' else 'None'}\nIDS_USERNAME_HASH={username_hash}\nIDS_PASSWORD_HASH={password_hash}\nIFACE={iface if iface else 'wlan0'}\nPORT={port}\nIP={ip if ip else 'None'}\n"
env_content_print = f"USE_TELEGRAM={str(use_telegram)}\nTELEGRAM_TOKEN={telegram_token if telegram_token != '' else 'None'}\nTELEGRAM_CHAT_ID={telegram_chat_id if telegram_chat_id != '' else 'None'}\nIDS_USERNAME_HASH=$HIDDEN$\nIDS_PASSWORD_HASH=$HIDDEN$\nIFACE={iface if iface else 'wlan0'}\nPORT={port}\nIP={ip if ip else 'None'}\n"

print("\nGenerated .env content:\n")
print(env_content_print)

if ask_bool("\nProceed?", True):
    with open(ENV_FILE, "w") as f:
        f.write(env_content)

    print("\n.env generated successfully.")
    print("IMPORTANT: store this file securely and do not share any sensitive information")

else:
    print("Aborted.")
    exit(0)