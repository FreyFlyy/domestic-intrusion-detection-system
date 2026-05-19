# LightIDS Web Dashboard — How to Use

The IDS dashboard is divided into three tabs: **Overview**, **Lists**, and **Settings**.
The UI refreshes automatically every `CAPTURE_DURATION` seconds (default 5s), while observed hosts are refreshed every 60s

---

## Login

Access the dashboard at `http://<server-ip>:<port>`.
Enter the configured username and password. After a period of inactivity the session expires and you are redirected back to the login page.
After 5 consecutive failed attempts from the same source, temporary access is restricted for 5 minutes.

---

## Overview Tab

The landing tab. Shows live traffic data and the current threat status at a glance.

### Time Statistics chart

Line chart of **packets per second (PPS)** over the last configured history window (default 300s).
Use it to spot traffic bursts or sustained floods at a glance.

### Top Sources chart

Horizontal bar chart of the **top 10 source IPs** by packet count, computed over the last `MAX_PACKETS_BUFFER` captured packets (default 25'000).
A source appearing here is not necessarily malicious — it just sends a lot of traffic.
Cross-reference with the Graylist below to assess whether it is also flagged.

### Graylist — Suspicious IPs

Table of IPs that exceeded the minimum alert score. Columns:

| Column | Meaning |
|--------|---------|
| **IP** | Source IP address |
| **Score** | Cumulative penalty score; higher = more suspicious. |
| **Flags** | Which attack signatures triggered (e.g. *SYN flood*, *Port scan*) |
| **SYN/ACK** | Peak SYN-to-ACK ratio observed (over `RECENT_HISTORY_TIMEFRAME`) |
| **RST-ed/SYN** | Peak ratio of RST packets received by this IP relative to its SYN count (connection probing indicator, over `RECENT_HISTORY_TIMEFRAME`) |
| **Port entropy** | Peak Shannon entropy of destination ports (high = many different ports = possible scan, over `RECENT_HISTORY_TIMEFRAME`) |
| **Std intervals** | Minimum standard deviation between packet timestamps (low = highly regular = likely automated, over `CAPTURE_DURATION`) |
| **Max PPS** | Peak packets per second from this IP (over `CAPTURE_DURATION`) |

**Clicking a row** expands a detail dropdown showing, for each metric, some other useful data regarding the flag and when it was last updated.

**NOTE:** *SYNs reported under the SYN/ACK and RST-ed/SYN dropdown rows might not be temporally aligned, as each metric is computed independently over separate sampling windows.*

**Actions per row:**
- **White** — move the IP to the whitelist; it will be ignored by the detector from now on and removed from the graylist immediately.
- **Watch** — add the IP to the watchlist for continuous monitoring without whitelisting it.
- **Reset** — pardon the IP: clears its stats and removes it from the graylist. Any traffic *before* the reset is ignored; scoring restarts from the next capture cycle.

**External links:**
- **IPinfo** — opens `ipinfo.io/<ip>` for geolocation and ASN lookup.
- **AbuseIPDB** — opens `abuseipdb.com/check/<ip>` to check the IP's abuse history.

**Clicking an IP** also redirects to its specific row under the *Observed Hosts* table, showing info such as its MAC, last seen and personalized notes

### Watchlist — Monitored IPs

Table of IPs explicitly added to the watchlist (from the graylist or the hosts list).
Shows both the **current** value and the **historical peak** for each metric (format: `current / peak`).
These IPs are monitored continuously but are not necessarily flagged as threats.

**Actions:** **Remove** (stop monitoring) or **Reset** (clear accumulated stats and remove the ip from the graylist if present).

Just like in the Graylist, **clicking a row** expands a detail dropdown showing, for each metric, some other useful data regarding the flag and when it was last updated.

Just like in the Graylist, **clicking an IP** also redirects to its specific row under the *Observed Hosts* table, showing info such as its MAC, last seen and personalized notes

---

## Lists Tab

Expanded, scrollable version of all four lists. Each section can be collapsed with the **▼** button.

### Observed Hosts

All hosts seen on the network in the last 24 hours (configurable via `HOSTS_WINDOW_SECONDS`).

| Column | Meaning |
|--------|---------|
| **IP** | Last seen IP for this host |
| **MAC** | Hardware address (available only for local network devices; '-' for external hosts) |
| **Name** | Vendor name (from MAC OUI lookup) for local hosts, or reverse DNS / ASN for external IPs |
| **Last Seen** | Timestamp of the last packet from this host |
| **Notes** | Free-text field, type and leave focus to save. Notes are persistent across restarts and keyed by MAC (local devices) or IP (external devices). |

**Actions:** **White** (whitelist the IP) or **Watch** (add to watchlist).

### Graylist

Same table as in the Overview tab, with the same click-to-expand and action buttons.

### Watchlist

Same table as in the Overview tab, with the same click-to-expand and action buttons.

### Whitelist

List of IPs excluded from analysis. The detector will never flag them regardless of traffic.

**Action:** **Remove** — the IP is removed from the whitelist and will be scored again from the next capture cycle.

---

## Settings Tab

Allows live adjustment of all detection parameters. Changes take effect immediately on the running detector without restarting the server.

### IDS Thresholds

These are the trigger levels for each detection signature. An IP is flagged for a given reason only when **all** conditions for that reason are met simultaneously (e.g. SYN/ACK ratio > threshold AND SYNs > min_syn_count).

| Setting | What it controls |
|---------|-----------------|
| **SYN/ACK Threshold** | Minimum SYN-to-ACK ratio to flag as SYN flood |
| **Min SYN Count** | Minimum number of SYN packets required before the SYN flood ratio is even checked |
| **RST/SYN Threshold** | Minimum RST-received-to-SYN ratio to flag as connection probing |
| **Min RST Count** | Minimum RST packet count required before the RST ratio is even checked |
| **Entropy Threshold** | Minimum port entropy to flag as port scan |
| **Min Std Intervals** | Maximum allowed inter-arrival time standard deviation (flag if std is below this value) |
| **PPS Threshold** | Minimum packets per second to flag as packet flood |

Raising a threshold makes the detector less sensitive for that signature; lowering it makes it more aggressive.

### Score Calculation — Penalties

Each triggered signature adds a fixed penalty to the IP's total score.
An IP enters the graylist only if its score reaches or exceeds **Min. Score for Alert**.

| Setting | Effect |
|---------|--------|
| **SYN flood** | Penalty added when SYN flood conditions are met (SYN/ACK ratio higher than threshold, and SYN count higher than the minimum syn count) |
| **Connection Probing** | Penalty added when RST/SYN conditions are met (RST-ed/SYN ratio higher than threshold, and RST-ed count higher than the minimum rst count) |
| **Port scan** | Penalty added when entropy threshold is exceeded |
| **Regular intervals** | Penalty added when interval std is lower than threshold |
| **Packet flood** | Penalty added when PPS threshold is exceeded |
| **Min. Score for Alert** | Minimum cumulative score to appear in the graylist |

Each triggered detection signature adds a fixed penalty to the IP score. Multiple triggers are cumulative.
Adjusting penalties or the minimum score immediately re-evaluates the current graylist and removes or retains entries accordingly.

Click **"Save IDS Thresholds"** or **"Save Penalties"** to apply changes. A timestamp confirms successful update.

---

## Theme and Logout

- **Dark 🌙 / Light ☀️** button (bottom right of the footer): toggles theme; preference is saved in `localStorage`.
- **Logout** button: clears the server-side session and redirects to the login page.