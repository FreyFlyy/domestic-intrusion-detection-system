# LightIDS (Intrusion Detection System)

![logo](/static/favicon.png)

![Version](https://img.shields.io/badge/version-v3.0-green.svg) [![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-red.svg)](https://www.gnu.org/licenses/agpl-3.0.html) ![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white) ![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)


A **lightweight, heuristic-based, customizable Intrusion Detection System (IDS)** for traffic analysis and anomaly detection.

Designed for **home labs**, it prioritizes low overhead and fully customizable heuristics over complex enterprise features, leaving part of the decision-making and tuning to the **user**, acting as a configurable analysis tool rather than a fully autonomous production-grade IDS.

*Note: As a passive Intrusion Detection System (IDS), this tool does not implement active countermeasures (e.g., IP blocking or blacklisting). It is designed solely for monitoring and visualization, with all response actions left to the user.*

## Table of Contents

0. [Getting started](#getting-started)
1. [Versions](#new-version-v30)
2. [Project structure](#project-structure)
3. [Workflow & Logic](#workflow--logic)
4. [Example detections](#example-detections)
5. [Technologies Used](#technologies-used)
6. [Performance](#performance)
7. [Known Criticalities](#known-criticalities)
8. [Future Implementations](#possible-future-implementations)
9.  [Screenshots](#screenshots-dark-theme)
10. [Author & License](#author)

---

## New version (v3.0)!

### FEATURES:

* **Data persistence over restarts**: graylists, watchlists, whitelists, thresholds, penalties and notes are now reloaded at startup and saved periodically (every 5 minutes) using an atomic SQLite database, reducing risk of data loss during crashes or restarts
* **Periodic metric cleanup**: reset logic for ports and SYN/ACK counters to remove stale historical data and prevent long-term accumulation from skewing anomaly detection
* **Mobile-friendly UI upgrade**: redesigned frontend with responsive layout improvements and more consistent control placement for mobile and low-resolution devices
* **Fast IP info lookup**: added direct links for graylisted IPs to external abuse/geolocation services. Clicking an IP now also instantly redirects to the Observed Hosts table, showing correlated MAC address and user-defined annotations

### SECURITY:

* **Salted credentials security upgrade**: adoption of `bcrypt` for password hashing with salt (and SHA256 pre-hashing), increasing resistance against rainbow table attacks and offline brute-force attempts
* **Login rate limiting**: enforced cooldown after 5 consecutive failed attempts, mitigating fast online brute-force attacks
* **Stronger thread locking enforcement**: improved synchronization in critical sections to reduce race conditions and inconsistent state updates under load

### FIXES:

* Corrected exclusion logic for **"Min score for alert"** in maximum score computation
* Fixed mismatch in HTML DOM identifiers for the **overview watchlist table**
* Fixed **reset behavior**: resetting a watchlisted IP no longer removes it, only clears its metrics as intended

## Project Structure

The repository is organized into a **backend analysis engine** and a **web-based visualization dashboard**:

### 1. Backend Engine
The **"brain"** of the system, responsible for raw data ingestion and packet analysis:
*   **`init.py`**: An **initialization file** aimed to set up the system in a one-time operation (including setting Telegram notifications, server IP and port, network interface and login credentials)
*   **`config.py`**: A dedicated **configuration file** to fine-tune anomaly thresholds (*e.g., SYN counts, entropy, PPS*), penalty scores and other configuration variables
*   **`server.py`**: The **central hub** that manages the `tshark` capture thread, processes packet batches, and serves the REST API via Flask

### 2. Frontend Dashboard (`/static`)
A web interface for real-time monitoring and administrative control with dual theme (light and dark):
*   **`index.html`**: The main dashboard hosting the traffic overview, host tables, and configuration tabs (*theme toggle button is on the bottom right*)
*   **`app.js`**: Handles asynchronous API communication and renders interactive charts using `Chart.js`
*   **`style.css`**: Provides styling for charts, tables, and general text formatting for readability and theme support

## Workflow & Logic

1.  **Capture**: The system utilizes a `tshark` subprocess to monitor the configured interface (`wlan0` by default, can be changed with `init.py`) in 5-second snapshots
2.  **Analyze**: Packets are processed to calculate various metrics, such as *port entropy* and *SYN/ACK ratios* (to identify port scans), *packet frequency* (to detect floods / DoS) and *interval variance* (to detect low-variance intervals, indicative of automated scanning)
3.  **Score**: Each IP is assigned a score based on a **penalty system**. If the score exceeds the *Minimum score for alert* the IP is moved to the **Graylist**.
4. **Visualize**: Real-time metrics are pushed to the UI at the configured host and port (default: `MACHINE_IP:8080`, can be changed with `init.py`), allowing users to manually move IPs to a **Whitelist** or monitor them via a priority **Watchlist**.

### Backend Workflow

![backend_workflow](/images/Backend_Workflow.png)

### Frontend Workflow

![frontend_workflow](/images/Frontend_Workflow.png)


## Example detections

### Attemped port scan
- High SYN/ACK ratio
- High destination port entropy
- High RST-ed/SYN ratio (if most of the victim device ports are closed/filtered)
- Low packet interval standard deviation
- Medium-high PPS with >3s central 90% window

### Packet flood (DoS)
- High PPS with >3s central 90% window
- Low mean intervals over capture duration
- Low destination port entropy
- Low proportion of SYN+ACK+RST/packets (commonly observed in ICMP flooding scenarios)

### Suspicious service probing
- High RST-ed/SYN ratio
- Repeated access attempts toward well-known registered ports (e.g. 22, 80, 443)

## Technologies Used

*   **Languages:** Python 3.x (*3.8 is the minimum requirement, but >=3.10 is recommended for improved performance and long-term support*), JavaScript (ES6+)
*   **Backend Frameworks:** `Flask`
*   **Network Analysis:** `tshark` (CLI Wireshark), `Subprocess`
*   **Frontend Libraries:** `Chart.js` (Real-time data viz)
*   **Data Management:** `Collections` (`deque`, `defaultdict`), `bcrypt` (credentials hashing)

**ATTENTION:** This IDS performs best when connected to a network TAP or via port mirroring (SPAN) on a managed switch. This ensures full visibility of network traffic at Layer 2/3, rather than being limited to traffic forwarded based on MAC address tables on standard switches.

## Performance

**Memory usage** typically starts at **~220MB** in idle conditions, but can increase to **~330MB** under extreme traffic conditions (e.g., sustained flooding or high-rate scanning scenarios approaching `MAX_PACKET_BUFFER` limits).

Measurements were taken on a **Raspberry Pi 5 (8GB RAM)** in a domestic environment with **10–12 active devices** and a **20Mbps** domestic network.

## **⚠️ Security Disclaimer ⚠️**

This system is not production-hardened: it is built for *trusted domestic environments*
*   **Potential vulnerabilities** include **XSS** in text inputs on the Observed Hosts table (even though already partially mitigated) and **client-side request tampering**
*   This service is currently **HTTP only**, so usage without any kind of VPN or Cryptographic tunnel can expose Cookies and **sensitive data**, possibly resulting in **MITM attacks** (Man-In-The-Middle) or **session hijacking**
*   Being an exclusively **Domestic** Intrusion Detection System, it does not implement **advanced malicious traffic filtering**: only give access to trusted users and do not share your credentials
*   Even with `bcrypt`, **authentication** is only as strong as configuration
*   **DO NOT expose this application to the public internet via simple port forwarding for any reason**
*   **The author assumes no responsibility for any security issues caused by misconfiguration or improper use**

## Known Criticalities

*   **Packet loss**: Packet loss is likely under high traffic due to buffer limits and non-streaming batch processing constraints
*   **Resource Saturation**: External API calls for MAC vendor and IP service resolution may cause delays under high network load.
*   **CPU Overhead**: Processing large packet buffers in Python can become CPU-intensive during significant traffic spikes due to non-vectorized processing and per-packet overhead.
*   **Metric Rigidity**: The current architecture requires manual code updates to implement entirely new detection metrics.
*   **Memory Growth**: While temporal pruning is implemented, extreme traffic may lead to significant memory usage in the `observed_hosts` cache.
*   **Possible race conditions and inefficiencies**: Thread synchronization is implemented in critical paths, though some auxiliary workflows are not yet fully optimized for concurrent scalability.

## Technical Notes

- **Central 90% window (`central_90_window`)**: the time span between the 5th and 95th percentile of packet timestamps within a capture window, enclosing the central 90% of observed events. Empirically, values of ~1–2 seconds indicate burst-like traffic characterized by short high-density transmission windows (typical of web browsing and legitimate connections), while values above ~3 seconds indicate sustained traffic patterns consistent with continuous probing or flooding activity.
*   **The "Reset" Logic**: Users can "reset" an IP's history, which ignores all packets captured before the reset timestamp, effectively "pardoning" the IP for its past behaviour

## Getting Started

### Linux

* **Prerequisites**: **Python 3.x** (*3.8 is the minimum requirement, but >=3.10 is recommended for improved performance and long-term support*), **JavaScript (ES6+)**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/FreyFlyy/light-ids.git
    cd light-ids
    ```
2.  **Install tshark:**
    ```bash
    sudo apt install tshark    # Ubuntu / Debian
    sudo dnf install wireshark-cli    # Fedora / RHEL, includes tshark
    sudo pacman -S wireshark-cli    # Arch Linux
    ```

3.  **Add user to Wireshark group:**
    
    **a. Configure for non-root capture (*Debian-based* distros only)**
    ```bash
    sudo dpkg-reconfigure wireshark-common
    ```
    And select *Yes*

    **b. Add user to Wireshark group**

    ```bash
    # Check if group exists
    getent group wireshark

    # Create group if missing
    sudo groupadd wireshark

    # Add user to group
    sudo usermod -aG wireshark $USER
    ```

    **c. Reboot the system to apply changes**


4.  **Install dependencies:** (Use of a virtual environment is recommended)
    ```bash
    # Create a virtual environment
    python3 -m venv VENV_NAME

    # Activate the environment
    source ./VENV_NAME/bin/activate

    # OPTIONAL: upgrade and clean pip
    pip install --upgrade pip
    pip cache purge

    # Install dependencies
    pip install -r requirements.txt
    ```

5.  **Set-up the system:**
    ```bash
    python init.py
    ```
    And follow **on-screen instructions**

6.  **Start the IDS:**
    ```bash
    python server.py
    ```

    See the web dashboard guide in `DASHBOARD.md`

## Screenshots (dark theme)

### "Overview" tab

![overview_tab](/images/Overview_tab.png)

### "Lists" tab

*Graylisted IP (192.168.1.100) and watched IP (192.168.1.100) on screen, showing its "worst" metrics (graylist), while also giving info on current metrics (watchlist)*

![lists_tab_1](/images/Lists_tab_1.png)

---

*Dropdown of the graylisted IP (192.168.1.100), showing different useful metrics for each category (e.g. SYNs, ACKs, Ports, Mean Packet interval...)*

![lists_tab_2](/images/Lists_tab_2.png)

---

*Hosts table showing all IPs seen in the last 24h, with the option to save personalized notes for each host*

![lists_tab_3](/images/Lists_tab_3.png)

---

## Author

**Francesco Scolz**
*   [LinkedIn](https://www.linkedin.com/in/francesco-scolz)
*   [GitHub](https://github.com/FreyFlyy)
*   [Hugging Face](https://huggingface.co/FreyFlyy)

  
## License

This project is licensed under the **[GNU AGPLsv3](https://www.gnu.org/licenses/agpl-3.0.html)**.

You may use, modify and distribute this software under the same license.
If you provide the software over a network, you must make the source code available to users.