// app.js

// Copyright (C) 2026 Francesco Scolz
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
// 
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// inintialize DOM elements (lists, forms...)
const errorDiv = document.getElementById('error-message');
const graylistBody = document.querySelector('#graylist-table tbody');
const graylistEmpty = document.getElementById('graylist-empty');
const listsHostsBody = document.querySelector('#lists-hosts-table tbody');
const listsHostsEmpty = document.getElementById('lists-hosts-empty');
const OverviewWatchlistBody = document.querySelector('#overview-watchlist-table tbody');
const OverviewWatchlistEmpty = document.getElementById('overview-watchlist-empty');
const listsWatchlistBody = document.querySelector('#lists-watchlist-table tbody');
const listsWatchlistEmpty = document.getElementById('lists-watchlist-empty');
const thresholdsForm = document.getElementById('thresholds-form');
const thresholdsStatus = document.getElementById('thresholds-status');
const penaltiesForm = document.getElementById('penalties-form');
const penaltiesStatus = document.getElementById('penalties-status');
const toggleBtn = document.getElementById('theme-toggle');


const listsGraylistBody = document.querySelector('#lists-graylist-table tbody');
const listsGraylistEmpty = document.getElementById('lists-graylist-empty');
const listsWhitelistBody = document.querySelector('#lists-whitelist-table tbody');
const listsWhitelistEmpty = document.getElementById('lists-whitelist-empty');

// initialize state
let statsChart = null; // chart instance (chart.js) for stats overview
let topSendersChart = null; // chart instance (chart.js) for top senders
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches; // default theme based on system preference

// configuration variables (will be loaded from server on startup, this is to avoid silent errors in case the config endpoint is not working and to have default values)
let THRESHOLDS = {};
let IFACE = 'wlan0';
let PORT = 8080;
let CAPTURE_DURATION = 5;
let MAX_PACKETS_BUFFER = 5000;
let GRAPH_HISTORY = 300;
let RECENT_HISTORY_TIMEFRAME = 3600;
let HOSTS_WINDOW_SECONDS = 86400;
let MAX_SCORE_POSSIBLE = 13;

const COMMON_PORTS = { // common ports mapping for better readability in the UI
    // --- Well-known ports (0-1023) ---
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    49: 'TACACS',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    69: 'TFTP',
    80: 'HTTP',
    88: 'KERBEROS',
    110: 'POP3',
    111: 'RPC',
    119: 'NNTP',
    123: 'NTP',
    135: 'MS RPC',
    137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM',
    139: 'NetBIOS-SSN',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMPTRAP',
    179: 'BGP',
    389: 'LDAP',
    427: 'SLP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    500: 'IPSEC-IKE',
    514: 'SYSLOG',
    515: 'LPD',
    520: 'RIP',
    546: 'DHCPV6-CLIENT',
    547: 'DHCPV6-SERVER',
    587: 'SMTP-SUBMISSION',
    623: 'IPMI',
    631: 'IPP',
    636: 'LDAPS',
    853: 'DNS-over-TLS',
    873: 'RSYNC',
    902: 'VMWARE',
    989: 'FTPS-DATA',
    990: 'FTPS',
    993: 'IMAPS',
    995: 'POP3S',

    // --- Registered ports useful in IDS ---
    1080: 'SOCKS',
    1194: 'OPENVPN',
    1433: 'MSSQL',
    1521: 'ORACLE',
    1701: 'L2TP',
    1723: 'PPTP',
    1812: 'RADIUS',
    1813: 'RADIUS-ACCT',
    1883: 'MQTT',
    2049: 'NFS',
    2181: 'ZOOKEEPER',
    2375: 'DOCKER-API',
    2376: 'DOCKER-API-TLS',
    3128: 'SQUID',
    3260: 'ISCSI',
    3306: 'MySQL',
    3389: 'RDP',
    3478: 'STUN',
    3690: 'SVN',
    4369: 'ERLANG-EPMD',
    5000: 'UPNP/FLASK',
    5044: 'LOGSTASH-BEATS',
    5060: 'SIP',
    5061: 'SIP-TLS',
    5432: 'PostgreSQL',
    5601: 'KIBANA',
    5672: 'RABBITMQ',
    5900: 'VNC',
    5985: 'WINRM-HTTP',
    5986: 'WINRM-HTTPS',
    6379: 'Redis',
    6443: 'KUBERNETES-API',
    6514: 'SYSLOG-TLS',
    6667: 'IRC',
    8000: 'HTTP-ALT',
    8080: 'HTTP-PROXY/ALT',
    8081: 'HTTP-ALT',
    8086: 'INFLUXDB',
    8443: 'HTTPS-ALT',
    8888: 'JUPYTER',
    9000: 'SONARQUBE',
    9092: 'KAFKA',
    9090: 'PROMETHEUS',
    9200: 'ELASTICSEARCH',
    9300: 'ELASTIC-NODE',
    9418: 'GIT',
    10050: 'ZABBIX-AGENT',
    10051: 'ZABBIX-SERVER',
    11211: 'MEMCACHED',
    27017: 'MongoDB',
    50000: 'DB2',
};


/// UTILITIES

async function fetchJson(url, timeoutMs = 5000) { // fetch wrapper with error handling and timeout
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, { signal: ctrl.signal });
        if (!res.ok) throw new Error(`Error in fetch ${url}: ${res.status} ${res.statusText}`);
        return res.json();
    } finally {
        clearTimeout(id);
    }
}

async function loadConfig() { // load config variables from server
    try {
        const res = await fetch('/api/config');
        const cfg = await res.json();

        THRESHOLDS = cfg.THRESHOLDS;
        IFACE = cfg.IFACE;
        PORT = cfg.PORT;
        CAPTURE_DURATION = cfg.CAPTURE_DURATION;
        MAX_PACKETS_BUFFER = cfg.MAX_PACKETS_BUFFER;
        GRAPH_HISTORY = cfg.GRAPH_HISTORY;
        RECENT_HISTORY_TIMEFRAME = cfg.RECENT_HISTORY_TIMEFRAME;
        HOSTS_WINDOW_SECONDS = cfg.HOSTS_WINDOW_SECONDS;

        document.querySelectorAll(".tooltip").forEach(el => { // replace placeholders in tooltips with actual values from config
            el.dataset.tooltip = el.dataset.tooltip.replaceAll(
            "${CAPTURE_DURATION}",
            CAPTURE_DURATION
            );
        });

    } catch (err) {
        showError("Error in config: " + err.message);
    }
}

function showError(msg) { // show error message in the UI
    errorDiv.textContent = msg;
    errorDiv.style.display = 'block';
}

function escHtml(str) { // escape HTML special characters to prevent XSS when rendering user-generated content in the UI (e.g., host notes), by replacing &, <, >, ", and ' with their respective HTML entities
    return String(str ?? '')
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#39;');
}

/// GRAPHS & STATS

async function refreshStats() { // load recent stats and top senders data from server and update the charts
    try {
        const data = await fetchJson('/api/stats');

        updateStatsChart(data.stats || []);
        updateTopSendersChart(data.top_sources || []);

    } catch(err) { 
        showError("Error in stats: " + err.message);
    }
}

function updateStatsChart(data) { // update the stats overview chart with recent data, showing the packets per second over time in a line chart
    if (!data.length) return;

    const labels = data.map(p =>
        new Date(p.ts * 1000).toLocaleTimeString([], { hour12: false })
    );

    const pps = data.map(p => p.pps ?? 0);

    if (!statsChart) { // first time: create the chart instance
        const ctx = document.getElementById('statsChart').getContext('2d');
        statsChart = new Chart(ctx, { // create new chart instance, with time on the x-axis and packets per second on the y-axis
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Packets per second',
                    data: pps,
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13,110,253,0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    y: { beginAtZero: true },
                    x: { type: 'category' }
                }
            }
        });
    } else { // update existing chart data
        statsChart.data.labels = labels;
        statsChart.data.datasets[0].data = pps;
        statsChart.update('none');
    }
}

function updateTopSendersChart(topSources = []) { // update the top senders chart with recent data, showing top sources in a bar graph
    const labels = topSources.map(([ip]) => ip);
    const counts = topSources.map(([, cnt]) => cnt);

    if (!topSendersChart) { // first time: create the chart instance
        const ctx = document.getElementById('topSendersChart').getContext('2d');
        topSendersChart = new Chart(ctx, { // create new chart instance, with IPs on the y-axis and packet counts on the x-axis, displayed as horizontal bars
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Packets (registered)',
                    data: counts,
                    backgroundColor: '#dc3545', 
                    borderColor: '#a31b29',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false
            }
        });
    } else { // update existing chart data
        topSendersChart.data.labels = labels;
        topSendersChart.data.datasets[0].data = counts;
        topSendersChart.update('none');
    }
}


/// HOSTS

async function refreshHosts() { // load hosts overview data from server and render in the table

    try {

        const res = await fetch('/api/hosts');
        const data = await res.json();

        listsHostsBody.innerHTML = ''; // clear previous data

        if (data.length === 0) { // if no hosts, show empty message
            listsHostsEmpty.style.display = 'block'; 
            return; 
        }
        listsHostsEmpty.style.display = 'none';

        data.forEach(h => { // render each host in the table
            const last_ip = h.last_ip || '-';
            const mac = h.mac || '-';
            const name = h.name || '-';
            const lastSeen = h.last_seen ? new Date(h.last_seen * 1000).toLocaleString([], { hour12: false }) : '-';

            const trL = document.createElement('tr'); // create new table row for each host, with space for personalized text notes
            trL.dataset.ip = last_ip;
            trL.innerHTML = `
                <td><code>${escHtml(last_ip)}</code></td>
                <td>${escHtml(mac)}</td>
                <td>${escHtml(name)}</td>
                <td>${escHtml(lastSeen)}</td>
                <td>
                    <input
                        type="text"
                        class="host-note-input"
                        value="${escHtml(h.note)}"
                        placeholder="Write a note"
                        data-mac="${escHtml(mac)}"
                        data-ip="${escHtml(last_ip)}"
                        onchange="saveHostNote(event)"
                        style="width: 100%;"
                    >
                </td>
                <td>
                    <button onclick="event.stopPropagation(); updateWhitelist('${escHtml(last_ip)}','add')">White</button><br>
                    <button onclick="event.stopPropagation(); addWatchlist('${escHtml(last_ip)}')">Watch</button>
                </td>
            `;
            listsHostsBody.appendChild(trL); // add row to the table body
        });
    } catch (err) {
        showError("Error in hosts: " + err.message);
    }
}

function jumpToObservedHost(ip) { // when clicking on an IP in the graylist overview, jump to the respective host in the hosts list

    // switch to Lists tab and Hosts subtab
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

    document.querySelector('[data-tab="tab-lists"]').classList.add("active");
    document.getElementById("tab-lists").classList.add("active");

    // open container if not already open
    const container = document.getElementById('lists-hosts-container');
    container.style.display = 'block';

    // find corresponding row in the hosts list
    const row = listsHostsBody.querySelector(`tr[data-ip="${ip}"]`);

    if (!row) showError("Host not found (" + ip + "), either it has not been added to the hosts lists, or it has been removed for inactivity."); // if not found, show error

    // scroll
    row.scrollIntoView({
        behavior: 'smooth',
        block: 'center'
    });

    // highlight
    row.classList.add('highlight-row');
    setTimeout(() => {
        row.classList.remove('highlight-row');
    }, 1500);
}

async function saveHostNote(event) { // save a note for a host by sending it to the server, identified by either its MAC or IP address
    const note = event.target.value.trim();
    const mac = event.target.dataset.mac;
    const ip  = event.target.dataset.ip;

    try {
        await fetch('/api/hosts/note', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac, ip, note }) // send the note along with the host's MAC and IP to the server to be saved in the host_notes dictionary
        });
    } catch (err) {
        showError("Error saving note: " + err.message);
    }
}

function toggleTable(id) { // toggle display of a table (used for the lists section to show/hide the graylist, watchlist and whitelist tables when clicking on the respective headers)
    const box = document.getElementById(id);

    if (box.style.display !== 'block') {
        box.style.display = 'block';
    } else {
        box.style.display = 'none';
    }
}


/// PENALTIES

async function loadPenaltiesAndMaxScore() { // load penalties values and max score
    const penalties = await fetchJson('/api/penalties');
    MAX_SCORE_POSSIBLE = Object.entries(penalties)
        .filter(([k]) => k !== "Minimum score for alert")  // exclude "Minimum score for alert" from the calculation
        .reduce((sum, [, v]) => sum + v, 0);
}


/// LISTS and DROPDOWNS

let openDropdowns = { graylist: new Set(), watchlist: new Set() }; // keep track of open dropdowns for graylist and watchlist to maintain their state when refreshing the lists

async function renderList({ containerBody, emptyContainer, items, type, maxScore = 1, whitelist = [], scrollY = null }) {
    const isGray = type === 'graylist';
    const isWatch = type === 'watchlist';
    containerBody.innerHTML = ''; // clean previous data

    let entries;
    switch (type) {
        case 'graylist': // for graylist, we filter out any IPs that are in the whitelist and sort the entries by score in descending order, so that the most suspicious IPs appear at the top of the list
            entries = Object.entries(items)
                .filter(([ip]) => !whitelist.includes(ip))
                .sort((a,b) => (b[1].score ?? 0) - (a[1].score ?? 0));
            break;
        case 'watchlist': // for watchlist, we just take the entries as they are
            entries = Object.entries(items);
            break;
        case 'whitelist': // for whitelist, we just take the entries as they are
            entries = items;
            break;
        default:
            entries = [];
    }

    if (!entries.length) { // if no entries, show empty message
        emptyContainer.style.display = 'block';
        return;
    }
    emptyContainer.style.display = 'none';

    const activeIps = new Set(
        entries.map(entry => Array.isArray(entry) ? entry[0] : entry)
    );

    entries.forEach(entry => { // for each entry in the list, create a table row with the relevant information, action buttons and event listeners
        const tr = document.createElement('tr');
        let ip, info;

        if (isGray) { // graylist
            [ip, info] = entry;
            const intensity = Math.min(1, (info.score ?? 0)/MAX_SCORE_POSSIBLE);
            const lightness = 70 - intensity * 30; // calculate lightness of the red color relative to score and max possible score
            tr.style.backgroundColor = `hsl(0 80% ${lightness}%)`;
            tr.classList.add('data-row');
            
            // display the IP, score, reasons, ratios, entropy, std intervals and max PPS for each entry in the graylist overview
            tr.innerHTML = `
                <td>
                    <code class="clickable-ip" onclick="event.stopPropagation(); jumpToObservedHost('${escHtml(ip)}')">
                        ${escHtml(ip)}
                    </code>
                </td>
                <td><strong>${escHtml(info.score ?? 0)}</strong></td>
                <td>${(info.reasons ?? []).join(', ') || '—'}</td>
                <td>${escHtml(info.ratio ?? '—')}</td>
                <td>${escHtml(info.rst_ratio ?? '—')}</td>
                <td>${escHtml(info.entropy ?? 0)}</td>
                <td>${escHtml(info.std_intervals ?? '—')}</td>
                <td>${escHtml(info.max_pps ?? 0)}</td>
                <td>
                    <button onclick="event.stopPropagation(); updateWhitelist('${escHtml(ip)}','add')">White</button><br>
                    <button onclick="event.stopPropagation(); addWatchlist('${escHtml(ip)}')">Watch</button><br>
                    <button onclick="event.stopPropagation(); resetIP('${escHtml(ip)}')">Reset</button>
                </td>
                <td>
                    <a href="https://ipinfo.io/${escHtml(ip)}" target="_blank">IPinfo</a><br>
                    <a href="https://www.abuseipdb.com/check/${escHtml(ip)}" target="_blank">AbuseIPDB</a>
                </td>
            `;

        } else if (isWatch) { // watchlist
            [ip, info] = entry;
            const ratio = `${info.ratio_current ?? '-'} / ${info.max_ratio ?? '-'}`;
            const entropy = `${info.entropy_current ?? '-'} / ${info.max_entropy ?? '-'}`;
            const std = `${info.std_current ?? '-'} / ${info.min_std ?? '-'}`;
            const pps = `${info.pps_current ?? '-'} / ${info.max_pps ?? '-'}`;
            const rst = `${info.rst_ratio_current ?? '-'} / ${info.max_rst_ratio ?? '-'}`;

            // display the IP, ratios, entropy, std intervals and max PPS for each entry in the watchlist overview
            tr.innerHTML = `
                <td>
                    <code class="clickable-ip" onclick="event.stopPropagation(); jumpToObservedHost('${escHtml(ip)}')">
                        ${escHtml(ip)}
                    </code>
                </td>
                <td>${escHtml(ratio)}</td>
                <td>${escHtml(rst)}</td>
                <td>${escHtml(entropy)}</td>
                <td>${escHtml(std)}</td>
                <td>${escHtml(pps)}</td>
                <td>
                    <button onclick="event.stopPropagation(); removeWatchlist('${escHtml(ip)}')">Remove</button><br>
                    <button onclick="event.stopPropagation(); resetIP('${escHtml(ip)}')">Reset</button>
                </td>
            `;
        } else { // whitelist
            ip = entry;
            // for whitelist, we just display the IP and a remove button
            tr.innerHTML = `
                <td>
                    <code class="clickable-ip" onclick="event.stopPropagation(); jumpToObservedHost('${escHtml(ip)}')">
                        ${escHtml(ip)}
                    </code>
                </td>
                <td>
                    <button onclick="event.stopPropagation(); updateWhitelist('${escHtml(ip)}','remove')">Remove</button>
                </td>
            `;

        }

        containerBody.appendChild(tr);

        // Dropdown click for graylist and watchlist
        if (isGray || isWatch) {
            tr.addEventListener('click', () => {
                const kind = isGray ? 'graylist' : 'watchlist';
                let next = tr.nextElementSibling;
                if (next && next.classList.contains(`${kind}-dropdown`)) { // if dropdown already open, close it
                    next.remove();
                    openDropdowns[kind].delete(ip);
                    return;
                }

                const dropdown = document.createElement('tr');
                dropdown.classList.add(`${kind}-dropdown`);
                const td = document.createElement('td');
                td.colSpan = tr.children.length;

                const metricNames = { // human-readable names for the metrics to display in the dropdown
                    max_ratio: "SYN/ACK",
                    max_entropy: "Port entropy",
                    min_std: "Std intervals",
                    max_pps: "Max PPS",
                    max_rst_ratio: "RST/SYN"
                };

                let html = `<table style="width:100%; margin-top:5px;">
                    <thead><tr><th>Metric</th><th>Value</th><th>Last updated</th></tr></thead><tbody>`;

                const metricOrder = [ // order of metrics to display in the dropdown
                    "max_ratio",
                    "max_rst_ratio",
                    "max_entropy",
                    "min_std",
                    "max_pps"
                ];

                metricOrder.forEach(metric => { // for each metric, get the display value and last updated time, then add a row to the dropdown table with this information
                    const value = getMetricValueDisplay(info, metric);
                    const lastUpdated = info.last_updated?.[metric] 
                                        ? new Date(info.last_updated[metric] * 1000).toLocaleString([], { hour12: false })
                                        : 'N/A';

                    html += `<tr>
                        <td>${metricNames[metric] || metric}</td>
                        <td>${value}</td>
                        <td>${lastUpdated}</td>
                    </tr>`;
                });

                html += `</tbody></table>`;
                td.innerHTML = html;
                dropdown.appendChild(td);
                tr.parentNode.insertBefore(dropdown, tr.nextSibling);

                if (!openDropdowns[isGray ? 'graylist' : 'watchlist'].has(ip)) // add the IP to the list of open dropdowns for the respective list type, so that it can be reopened after a refresh if it was open before
                    openDropdowns[isGray ? 'graylist' : 'watchlist'].add(ip);
            });
        }
    });

    if (!isGray && !isWatch) {
        if (scrollY !== null) window.scrollTo(0, scrollY);
        return;
    }

    const kind = isGray ? 'graylist' : 'watchlist';

    // filter out any IPs not present anymore in graylist or watchlist
    for (const ip of openDropdowns[kind]) {
        if (!activeIps.has(ip)) openDropdowns[kind].delete(ip);
    }

    openDropdowns[kind].forEach(ip => { // after rendering the list, we check which dropdowns were open before the refresh and we try to reopen them by simulating a click on the respective row
        const rows = Array.from(containerBody.querySelectorAll('tr'));
        for (const row of rows) {
            const ipRow = row.querySelector('td code')?.textContent.trim();
            if (ipRow === ip) {
                row.click();
                break;
            }
        }
    });

    // restore scroll position after rendering, so that the user doesn't lose their place in the list when it refreshes
    if (scrollY !== null) {
        setTimeout(() => window.scrollTo(0, scrollY), 0);
    }
}

function getMetricValueDisplay(info, metric) { // get the display value for a specific metric based on the info object for an IP entry, formatting it in a human-readable way depending on the type of metric (e.g., showing SYN/ACK counts for max_ratio, listing ports for max_entropy, showing mean interval for min_std, and showing 90th percentile window and packet count for max_pps)
    switch(metric) {
        case 'max_ratio': // SYN/ACK
            return `SYN: ${info.syn_count || 0} / ACK: ${info.ack_count || 0}`;
        case 'max_rst_ratio': // RST-ed/SYN
            return `RST-ed: ${info.rst_count || 0} / SYN: ${info.syn_count_rstsyn || 0}`;
        case 'max_entropy': // Port entropy
        if (info.used_ports && info.used_ports.length) {
            const portsWithNames = info.used_ports.map(p => {
                const n = parseInt(p, 10);
                return COMMON_PORTS[n] ? `${n} (${COMMON_PORTS[n]})` : `${n}`; // add port info if available
            });

            return `Ports (dst): ${portsWithNames.join(', ')}`;
        } else {
            return `Ports (dst): -`;
        }
        case 'min_std': // Intervals
            return `Mean interval between packets: ${info.mean_intervals || '-'}`;
        case 'max_pps': // PPS
            return `Central 90% window: ${info.central_90_window || '-'} s | Captured packets: ${info.packet_count || '-'}`;
        default:
            return '-';
    }
}

async function refreshGraylist() { // refresh graylist data by reloading from server and rendering in the table
    try {
        const data = await fetchJson('/api/graylist');
        const scrollY = window.scrollY;
        renderList({ // render graylist overview
            containerBody: graylistBody,
            emptyContainer: graylistEmpty,
            items: data || {},
            type: 'graylist',
            scrollY: null
        });
        renderList({ // render graylist lists
            containerBody: listsGraylistBody,
            emptyContainer: listsGraylistEmpty,
            items: data || {},
            type: 'graylist',
            scrollY
        });
    } catch (err) {
        showError('Error in graylist: ' + err.message);
    }
}

async function refreshWatchlist() { // refresh watchlist data by reloading from server and rendering in the tables
    try {
        const data = await fetchJson('/api/watchlist');
        const scrollY = window.scrollY;
        renderList({ // render watchlist overview
            containerBody: OverviewWatchlistBody,
            emptyContainer: OverviewWatchlistEmpty,
            items: data || {},
            type: 'watchlist',
            scrollY: null
        });

        renderList({ // render watchlist lists
            containerBody: listsWatchlistBody,
            emptyContainer: listsWatchlistEmpty,
            items: data || {},
            type: 'watchlist',
            scrollY
        });

    } catch (err) {
        showError('Error in watchlist: ' + err.message);
    }
}

async function refreshWhitelist() { // refresh whitelist data by reloading from server and rendering in the table
    try {
        const data = await fetchJson('/api/whitelist');
        const scrollY = window.scrollY;
        renderList({ // render whitelist lists
            containerBody: listsWhitelistBody,
            emptyContainer: listsWhitelistEmpty,
            items: data || [],
            type: 'whitelist',
            scrollY
        });
    } catch (err) {
        showError('Error in whitelist: ' + err.message);
    }
}

async function resetIP(ip) { // "pardon" an IP in the graylist by sending a request to the server, then refresh all relevant data
    try {
        await fetch('/api/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        await Promise.all([refreshStats(), refreshGraylist(), refreshWatchlist()]); // refresh all relevant data after resetting the IP's score
    } catch (err) {
        showError('Error in reset: ' + err.message);
    }
}

async function addWatchlist(ip) { // add an IP to the watchlist by sending a request to the server, then refresh the watchlist data
    try {
        await fetch('/api/watchlist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        await refreshWatchlist(); // refresh watchlist data after adding the IP
    } catch (err) {
        showError('Error in watchlist: ' + err.message);
    }
}

async function removeWatchlist(ip) { // remove an IP from the watchlist by sending a request to the server, then refresh the watchlist data
    try {
        await fetch('/api/watchlist/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        await Promise.all([refreshStats(), refreshWatchlist()]); // refresh watchlist data after removing the IP
    } catch (err) {
        showError('Error in watchlist: ' + err.message);
    }
}

async function updateWhitelist(ip, action) { // add or remove an IP from the whitelist by sending a request to the server, then refresh all relevant data
    try {
        await fetch(`/api/whitelist/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        await Promise.all([refreshStats(), refreshWhitelist(), refreshGraylist()]); // refresh all relevant data after updating the whitelist
    } catch (err) {
        showError('Error in whitelist: ' + err.message);
    }
}


/// TAB INTERACTIONS

document.querySelectorAll(".tab-btn").forEach(btn => { // add click event listeners to all tab buttons to handle tab switching
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;

    // buttons
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");

    // Contents
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    document.getElementById(tab).classList.add("active");
  });
});


/// LOAD SETTINGS & PENALTIES

async function loadThresholds() { // fetch current threshold settings from server and populate the form inputs
  try {
    const res = await fetch('/api/thresholds');
    const data = await res.json();

    for (const key in data) { // populate form inputs with current settings values
      const input = document.getElementById(key);
      if (input) input.value = data[key];
    }

    thresholdsStatus.textContent = ''; // clear any previous status messages
  } catch(err) { 
        showError("Error in thresholds: " + err.message);
    }
}

async function loadPenalties() { // fetch current penalties settings from server and populate the form inputs
  try {
    const res = await fetch('/api/penalties');
    const data = await res.json();

    for (const key in data) { // populate form inputs with current penalties values
      const input = document.querySelector(`#penalties-form input[name="${key}"]`);
      if (input) input.value = data[key];
    }

    penaltiesStatus.textContent = ''; // clear any previous status messages
  } catch (err) {
    showError("Error in penalties: " + err.message);
  }
}


/// SAVE SETTINGS & PENALTIES

thresholdsForm.addEventListener('submit', async (e) => { // handle thresholds form submission by sending updated values to the server, then show success/error message
  e.preventDefault();

  const formData = new FormData(thresholdsForm); // extract form data into an object to send to the server
  const payload = {};
  formData.forEach((v, k) => payload[k] = parseFloat(v));

  try {
    const res = await fetch('/api/thresholds', { // send updated thresholds to server
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Error in saving');

    // if thresholds are updated successfully, show success message with timestamp
    const ts = new Date().toLocaleString([], { hour12: false });
    thresholdsStatus.textContent = `Thresholds saved! ${ts}`;
    thresholdsStatus.style.color = 'green';

    await loadPenaltiesAndMaxScore()
    await Promise.all([refreshStats(), refreshGraylist(), refreshWhitelist(), refreshWatchlist()]); // refresh all relevant data to reflect new settings
  } catch (err) {
    showError('Error in thresholds: ' + err.message);
  }
});

penaltiesForm.addEventListener('submit', async (e) => { // handle penalties form submission by sending updated values to the server, then show success/error message and refresh relevant data
  e.preventDefault();

  const formData = new FormData(penaltiesForm); // extract form data into an object to send to the server
  const payload = {};
  formData.forEach((v, k) => payload[k] = parseFloat(v));

  try {
    const res = await fetch('/api/penalties', { // send updated penalties to server
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Error in saving');

    // if penalties are updated successfully, show success message with timestamp and refresh all relevant data to reflect new penalties
    const ts = new Date().toLocaleString([], { hour12: false });
    penaltiesStatus.textContent = `Penalties saved! ${ts}`;
    penaltiesStatus.style.color = 'green';

    await loadPenaltiesAndMaxScore()
    await Promise.all([refreshStats(), refreshGraylist(), refreshWhitelist(), refreshWatchlist()]);
  } catch (err) {
    showError('Error in penalties: ' + err.message);
  }
});


/// THEME TOGGLE and LOGOUT
const savedTheme = localStorage.getItem('theme'); // check if user has a saved theme preference in localStorage
if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
  document.body.classList.add('dark-theme');
  toggleBtn.textContent = 'Light ☀️';
}

function updateLogo() { // update the logo image based on the current theme
    const logo = document.querySelector(".logo");
    if (!logo) return;
    const isDark = document.body.classList.contains("dark-theme");
    logo.src = isDark
        ? "/static/Logo_dark.png"
        : "/static/Logo.png";
}

toggleBtn.addEventListener('click', () => { // toggle between light and dark themes when the theme toggle button is clicked and save the preference in localStorage
  const isDark = document.body.classList.toggle('dark-theme');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  toggleBtn.textContent = isDark ? 'Light ☀️' : 'Dark 🌙';
  updateLogo();
});

async function logout() { // handle user logout by sending a request to the server to clear the session, then redirect to the login page
    await fetch('/logout', { method: 'POST' });
    window.location.href = '/login';
}


/// INITIAL LOAD

async function init() {
    // load initial configuration, thresholds and penalties from server before loading any data to ensure the frontend logic has the necessary parameters to function correctly
    await loadConfig();
    await loadThresholds();
    await loadPenalties();
    await loadPenaltiesAndMaxScore();

    // set dynamic title based on config values
    document.getElementById('top-sources-title').textContent =
        `Top Sources (last ${MAX_PACKETS_BUFFER} packets)`;

    // initial refresh of all data to populate the UI on page load
    await Promise.all([
        refreshStats(),
        refreshGraylist(),
        refreshWatchlist(),
        refreshWhitelist(),
        refreshHosts()
    ]);

    updateLogo();

    // auto-refresh
    setInterval(refreshStats, CAPTURE_DURATION*1000);
    setInterval(refreshGraylist, CAPTURE_DURATION*1000);
    setInterval(refreshWatchlist, CAPTURE_DURATION*1000);
    setInterval(refreshWhitelist, CAPTURE_DURATION*1000);
    setInterval(refreshHosts, 60*1000);
}

init(); // start the application by initializing everything on page load