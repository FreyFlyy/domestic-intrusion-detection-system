# Domestic Network Intrusion Detection System (IDS)

A **lightweight, highly customizable Intrusion Detection System (IDS)** for **real-time traffic analysis** and **anomaly detection.**

Designed for **home labs** and **constrained environments**, it prioritizes **low overhead** and **fully customizable heuristics** over complex enterprise features.

*Note: As a passive Intrusion Detection System (IDS), this tool does not implement active countermeasures (e.g., IP blocking or blacklisting). It is designed solely for monitoring and visualization, with all response actions left to the user.*

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC_BY--NC--SA_4.0-red)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

## Table of Contents
0. [Getting started](#getting-started)
1. [Versions](#new-version-v20)
2. [Project structure](#project-structure)
3. [Workflow & Logic](#workflow--logic)
4. [Technologies Used](#technologies-used)
5. [Performance](#performance)
6. [Known Criticalities](#known-criticalities)
7. [Future Implementations](#possible-future-implementations)
8. [Screenshots](#screenshots-dark-theme)
9. [Author & License](#author)

---

## New version (v2.0)!

* **Dropdown Tables for Graylist/Watchlist**: Each metric now shows **Last Update** and **useful metrics**. These include:
    * **SYN/ACK** → Number of SYNs and ACKs
    * **Port Entropy** → Observed ports
    * **Std Δt** → Mean interval between packets
    * **Max PPS** → Time window of the 95th percentile and total packets
* **Duplicate IP Handling**: **Multiple IP** entries are **skipped** to avoid inconsistencies.
* **Telegram Bot Integration** (Optional): Configurable notifications for **alerts** and **graylistings**.
* **Authentication**:
    * `/login` - requires **username** and **password**
    * `/logout` - added **button** on the bottom right
* **PPS Calculation**: Uses **95th percentile window**; if traffic is concentrated in **short bursts**, the **full capture duration** is considered to **smooth regular traffic spikes**.
* Added **Last Seen** and a **Notes field** in **Observed Hosts list** (personalized notes, can be used to **identify devices/services** or keep track of **attack patterns**)
* **Sensitive data** moved to `.env` file (industry standard)
* **Ephemeral ports** (≥ 49152) are now **ignored** for analysis (as they're rarely scanned and mostly used by clients for temporary connections, so they could false some IPs)

## Project Structure

The repository is organized into a **backend analysis engine** and a **web-based visualization dashboard**:

### 1. Backend Engine
The **"brain"** of the system, responsible for **raw data ingestion** and **packet analysis**:
*   **`config.py`**: A dedicated **configuration file** to **fine-tune anomaly thresholds** (*e.g., SYN counts, entropy, PPS*) and **penalty scores**.
*   **`ids_server.py`**: The **central hub** that manages the **`tshark` capture thread, processes packet batches**, and serves the **REST API** via **Flask**.

### 2. Frontend Dashboard (`/static`)
A **modern** interface for **real-time monitoring** and **administrative control** with **dual theme** (light and dark):
*   **`index.html`**: The main dashboard hosting the **traffic overview, host tables, and configuration tabs** (*theme toggle button is on the bottom right*).
*   **`app.js`**: Handles **asynchronous API communication** and **renders interactive charts** using `Chart.js`.
*   **`style.css`**: Provides **styling for charts, tables, and general text formatting** for readability and theme support.

## Workflow & Logic

1.  **Capture**: The system utilizes a **`tshark` subprocess** to monitor the configured interface (`wlan0` by default, can be changed in `config.py`) in 5-second snapshots.
2.  **Analyze**: Packets are processed to **calculate various metrics**, such as *port entropy* and *SYN/ACK ratios* (to identify port scans), *packet frequency* (to detect floods / DoS) and *interval variance* (to detect low-variance intervals, indicative of automated scanning).
3.  **Score**: Each IP is assigned a **score** based on a **Penalty System**. If the score exceeds the *Minimum score for alert* the IP is moved to the **Graylist**.
4. **Visualize**: **Real-time metrics** are pushed to the UI at the configured **host** and **port** (**default: MACHINE_IP:8080**, can be changed in `config.py`), allowing users to **manually move IPs** to a **Whitelist** or monitor them via a priority **Watchlist**.

### Backend Workflow

![backend_workflow](/images/Backend_Workflow.png)

### Frontend Workflow

![frontend_workflow](/images/Frontend_Workflow.png)


## Technologies Used

*   **Languages:** Python 3.x (*3.8 is the minimum requirement, but >=3.10 is recommended for improved performance and long-term support*), JavaScript (ES6+)
*   **Backend Frameworks:** Flask, Flask-CORS
*   **Network Analysis:** Tshark (Wireshark), Subprocess
*   **Frontend Libraries:** Chart.js (Real-time data viz)
*   **Data Management:** Collections (deque, defaultdict)

## Performance

**As a reference point**, under **typical home network conditions** (~15 active devices), the **IDS** runs at **~2–4% CPU** on a **Raspberry Pi 5 (8GB)**.
**CPU usage** may increase significantly under **high traffic spikes** due to **Python-based packet processing**.

**Memory usage** typically starts at **~150MB** and may increase to **~200MB** under **high traffic conditions** due to **in-memory host tracking and packet buffering.**

## **⚠️ Security Disclaimer ⚠️**

**This project currently lacks an authentication layer.** 
*   Especially with the new version *(v2.0)*, **Cross Site Scripting (XSS) vulnerabilities** are possible through textboxes
*   Even if **username** and **password** are **hashed** they can still be **reversed** using **rainbow tables** and other techniques
*   **DO NOT** expose this application to the public internet via port forwarding **for any reason**. 
*   Use exclusively in **trusted local environments** (such as domestic networks) or via a **secure VPN.**
*   **The author assumes no responsibility for any security issues caused by misconfiguration or improper use.**

## Known Criticalities

*   **Resource Saturation**: External API calls for MAC vendor and IP service resolution may cause **delays** under **high network load.**
*   **CPU Overhead**: Processing **large packet buffers** in Python can become **CPU-intensive** during significant traffic spikes due to **non-vectorized processing** and **per-packet overhead.**
*   **Metric Rigidity**: The current architecture requires **manual code updates** to implement entirely **new detection metrics**.
*   **Memory Growth**: While temporal pruning is implemented, **extreme traffic** may lead to **significant memory usage** in the `observed_hosts` cache.

## Possible Future Implementations

### Medium Priority
*   **Data Persistence**: Integration of a **saving/loading architecture** to save and reload **lists** and **historical chart data** across **restarts**.
*   **Naming System**: Ability to assign **custom aliases** to **specific IP addresses** for easier identification.

### Experimental
*   **ML-Driven Scoring**: Replacing **static penalties** with **adaptive Machine Learning models** to calculate threat scores **dynamically.**


## Technical Notes

*   **PPS Threshold**: Packets Per Second (PPS) are calculated over the full `CAPTURE_DURATION` interval if the **95th percentile** of packets occurs within less than **2.5 seconds**. This adjustment smooths out **normal traffic bursts** that can arise from basic and legitimate activities such as web browsing. Otherwise, the **95th percentile range** is used to calculate **PPS**. If this range is *similar* to the **capture duration** (default 5 s), it may indicate **constant traffic**, *uncommon during normal daily activities*, and could be a sign of a **flood** when combined with **high PPS values**.
*   **The "Pardon" Logic**: Users can **"reset"** an IP's history, which **ignores all packets captured before the reset timestamp**, effectively **"pardoning"** the IP for a **tantum**

## Getting Started

### Linux

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/FreyFlyy/domestic-intrusion-detection-system.git
    cd domestic-intrusion-detection-system
    ```
2.  **Install tshark:**
    ```bash
    sudo apt install tshark    # Ubuntu / Debian
    sudo dnf install wireshark-cli    # Fedora / RHEL, includes tshark
    sudo pacman -S wireshark-cli    # Arch Linux
    ```
3.  **Install dependencies:** (Use of a virtual environment is recommended)
    ```bash
    pip install -r requirements.txt
    ```

4.  **Change the Network Interface (default `wlan0`):**
    ```bash
    nano config.py
    ```
    And edit the `IFACE` variable as needed (es. any, eth0, ...)

5.  **Edit `.env` file**
    ```bash
    nano .env
    ```
    Put the **hashes** of your chosen **username** and **password** (***DO NOT SHARE***) and, optionally, configure a **telegram bot** by providing `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` (and setting `USE_TELEGRAM` as True)

6.  **Start the IDS:**
    ```bash
    python ./ids_server.py
    ```

**NOTE:**
* Remember to set the correct network interface in `config.py` under the `IFACE` variable (default is `wlan0`).
* **REMEMBER TO CHANGE THE USERNAME AND PASSWORD FOR THE LOGIN PAGE!**. Edit the `.env` file by pasting the **SHA256 hash** of **YOUR PERSONALIZED username and password** (you can use different tools to calculate SHA256 of a string, such as [this one](https://emn178.github.io/online-tools/sha256.html))

    
## Screenshots (dark theme)

### "Overview" tab

![overview_Tab](/images/Overview_tab.png)

### "Lists" tab

![lists](/images/Lists_tab_1.png)

![lists](/images/Lists_tab_2.png)

## Author

**Francesco Scolz**
*   [LinkedIn](https://www.linkedin.com/in/francesco-scolz/)
*   [GitHub](https://github.com/FreyFlyy)
*   [Hugging Face](https://huggingface.co/FreyFlyy)

  
## License

This project is released under the **CC BY-NC-SA 4.0** license.  
For more information, see [CreativeCommons website](https://creativecommons.org/licenses/by-nc-sa/4.0/)
