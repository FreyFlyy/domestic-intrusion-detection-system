// app.js

// inintialize DOM elements (lists, forms...)
const errorDiv = document.getElementById('error-message');
const graylistBody = document.querySelector('#graylist-table tbody');
const graylistEmpty = document.getElementById('graylist-empty');
const listsHostsBody = document.querySelector('#lists-hosts-table tbody');
const listsHostsEmpty = document.getElementById('lists-hosts-empty');
const watchlistBody = document.querySelector('#lists-watchlist-table tbody');
const watchlistEmpty = document.getElementById('lists-watchlist-empty');
const listsWatchlistBody = document.querySelector('#lists-watchlist-table-lists tbody');
const listsWatchlistEmpty = document.getElementById('lists-watchlist-empty-lists');
const settingsForm = document.getElementById('settings-form');
const settingsStatus = document.getElementById('settings-status');
const penaltiesForm = document.getElementById('penalties-form');
const penaltiesStatus = document.getElementById('penalties-status');
const toggleBtn = document.getElementById('theme-toggle');


const listsGraylistBody = document.querySelector('#lists-graylist-table tbody');
const listsGraylistEmpty = document.getElementById('lists-graylist-empty');
const listsWhitelistBody = document.querySelector('#lists-whitelist-table tbody');
const listsWhitelistEmpty = document.getElementById('lists-whitelist-empty');

// initialize state
let hostsLoaded = false; // hosts hidden by default
let statsChart = null; // chart instance (chart.js) for stats overview
let topSendersChart = null; // chart instance (chart.js) for top senders
let hostNotes = JSON.parse(localStorage.getItem('hostNotes') || '{}'); // local notes for hosts, keyed by MAC or IP, stored in localStorage to persist across sessions
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches; // default theme based on system preference

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

async function fetchJson(url) { // fetch wrapper with error handling
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Errore fetch ${url}`);
    return res.json();
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
        STATS_KEEP = cfg.STATS_KEEP;
        TOP_WINDOW_SECONDS = cfg.TOP_WINDOW_SECONDS;
        HOSTS_WINDOW_SECONDS = cfg.HOSTS_WINDOW_SECONDS;

    } catch (err) {
        showError("Error in config: " + err.message);
    }
}

function showError(msg) { // show error message in the UI
    errorDiv.textContent = msg;
    errorDiv.style.display = 'block';
}


/// GRAPHS & STATS

async function refreshStats() { // load recent stats and top senders data from server and update the charts
    try {
        const data = await fetchJson('/api/stats'); // fetch stats data from server

        updateStatsChart(data.stats || []);
        updateTopSendersChart(data.top_sources || []);

    } catch(err) { 
        showError("Error in stats: " + err.message);
    }
}

function updateStatsChart(data) { // update the stats overview chart with recent data
    const cutoff = Date.now()/1000 - STATS_KEEP; // show only last STATS_KEEP seconds
    const recent = data.filter(p => p.ts >= cutoff); // filters only recent data points
    if (recent.length === 0) return;

    const labels = recent.map(item =>
        new Date(item.ts * 1000).toLocaleTimeString() // formats timestamp to human-readable time for x-axis labels
    );
    const pps = recent.map(item => item.pps ?? 0); // extracts packets-per-second values, defaulting to 0 if missing

    if (!statsChart) { // first time: create chart instance
        const ctx = document.getElementById('statsChart').getContext('2d');
        statsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        label: 'Packets per second',
                        data: pps,
                        borderColor: '#0d6efd',
                        backgroundColor: 'rgba(13,110,253,0.1)',
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true },
                    x: { type: 'category'}
                }
            }

        });
    } else { // update existing chart data
        statsChart.data.labels = labels;
        statsChart.data.datasets[0].data = pps;
        statsChart.update('none');
    }
}

function updateTopSendersChart(topSources = []) { // update the top senders chart with recent data
    const labels = topSources.map(([ip]) => ip); // extracts IP addresses for y-axis labels
    const counts = topSources.map(([, cnt]) => cnt); // extracts packet counts for each sender

    if (!topSendersChart) { // first time: create chart instance
        const ctx = document.getElementById('topSendersChart').getContext('2d');
        topSendersChart = new Chart(ctx, {
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

async function loadHosts() { // load hosts overview data from server and render in the table
    listsHostsBody.innerHTML = '';

    const overviewTable = document.querySelector('#hosts-table tbody'); // element for hosts overview table body
    if (overviewTable) {
        overviewTable.innerHTML = ''; // clear previous data
    }

    const res = await fetch('/api/hosts'); // fetch hosts data from server
    const data = await res.json(); // parse JSON response

    if (data.length === 0) { // if no hosts, show empty message
        listsHostsEmpty.style.display = 'block'; 
        return; 
    }
    listsHostsEmpty.style.display = 'none'; // hide empty message

    data.forEach(h => { // render each host in the table
        const last_ip = h.last_ip || '-';
        const mac = h.mac || '-';
        const name = h.name || '-';
        const lastSeen  = h.last_seen ? new Date(h.last_seen  * 1000).toLocaleString() : '-';

        const trL = document.createElement('tr'); // create new table row for each host, with space for personalized text notes
        trL.innerHTML = `
            <td><code>${last_ip}</code></td>
            <td>${mac}</td>
            <td>${name}</td>
            <td>${lastSeen}</td>
            <td>
                <input
                    type="text"
                    value="${h.note || ''}"
                    placeholder="Write a note"
                    onchange="saveHostNote(event, '${mac}', '${last_ip}')"
                    style="width: 100%;"
                >
            </td>
            <td>
                <button onclick="event.stopPropagation(); updateWhitelist('${last_ip}','add')">White</button><br>
                <button onclick="event.stopPropagation(); addWatchlist('${last_ip}')">Watch</button>
            </td>
        `;
        listsHostsBody.appendChild(trL); // add row to the table body
    });
}

async function saveHostNote(event, mac, ip) { // save a note for a host by sending it to the server, identified by either its MAC or IP address. The note is stored in the host_notes dictionary on the server and can be used to add custom comments or observations about specific hosts in the UI, which can be helpful for tracking and investigation purposes
    const note = event.target.value.trim();

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

function toggleListsHosts() { // toggle visibility of hosts in lists overview
    const box = document.getElementById('lists-hosts-container'); // element for hosts in lists overview container
    box.style.display = box.style.display === 'none' ? 'block' : 'none'; // toggle display
}

async function refreshHosts() { // refresh hosts data by reloading from server
    await loadHosts();
}


/// PENALTIES

async function loadPenaltiesAndMaxScore() { // load penalties settings from server and calculate the maximum possible score based on the sum of all penalties, which is used to determine the intensity of the red color for entries in the graylist (higher score means more intense red)
    try {
        const penalties = await fetchJson('/api/penalties');
        MAX_SCORE_POSSIBLE = Object.values(penalties).reduce((a,b) => a+b, 0);
    } catch (err) {
        showError("Error in penalties: " + err.message);
    }
}


/// LISTS and DROPDOWNS

function createDropdown(tr, info, kind) { // create a dropdown element with detailed metrics for a given IP entry in the graylist or watchlist, showing values like SYN/ACK packets, used ports, mean interval value, 95th percentile time window and total packets sent, along with the last updated time for each metric. The dropdown is inserted right after the clicked row in the table and can be toggled by clicking on the same row again.
    const dropdown = document.createElement('tr');
    dropdown.classList.add(`${kind}-dropdown`);
    const td = document.createElement('td');
    td.colSpan = tr.children.length;

    const metricNames = { // human-readable names for the metrics to display in the dropdown
        max_ratio: "SYN/ACK",
        max_entropy: "Port entropy",
        min_std: "Std Δt",
        max_pps: "Max PPS"
    };

    let html = `<table style="width:100%; margin-top:5px;">
        <thead><tr><th>Metric</th><th>Value</th><th>Last updated</th></tr></thead><tbody>`;

    const metricOrder = [ // order of metrics to display in the dropdown
        "max_ratio",
        "max_entropy",
        "min_std",
        "max_pps"
    ];

    metricOrder.forEach(metric => { // for each metric, get the display value and last updated time, then add a row to the dropdown table with this information
        const value = getMetricValueDisplay(info, metric);
        const lastUpdated = info.last_updated?.[metric]
                            ? new Date(info.last_updated[metric]*1000).toLocaleString()
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
}


let openDropdowns = { graylist: [], watchlist: [] }; // keep track of open dropdowns for graylist and watchlist to maintain their state when refreshing the lists, so that if a dropdown was open before the refresh, it will be reopened after the refresh if the same IP is still present in the data

function renderList({ containerBody, emptyContainer, items, type, maxScore = 1, whitelist = [] }) {
    const isGray = type === 'graylist';
    const isWatch = type === 'watchlist';
    const scrollY = window.scrollY; // save scroll position to restore it after rendering, so that the user doesn't lose their place in the list when it refreshes
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

    if (!entries.length) {
        emptyContainer.style.display = 'block';
        return;
    }
    emptyContainer.style.display = 'none';

    entries.forEach(entry => { // for each entry in the list, create a table row with the relevant information and action buttons, and add event listeners for the buttons and row clicks to handle interactions like adding to watchlist, removing from lists, resetting graylist score, and showing the dropdown with detailed metrics
        const tr = document.createElement('tr');
        let ip, info;

        if (isGray) { // graylist
            [ip, info] = entry;
            const intensity = Math.min(1, (info.score ?? 0)/maxScore); // calculate intensity of red color based on the score of the IP relative to the maximum possible score
            tr.style.backgroundColor = `rgba(231,21,21,${intensity})`;
            tr.classList.add('data-row');
            
            // display the IP, score, reasons, ratio, entropy, std intervals and max PPS for each entry in the graylist overview, along with action buttons to add to whitelist, add to watchlist and reset the score (pardon), and links to external services for further investigation of the IP
            tr.innerHTML = `
                <td><code>${ip}</code></td>
                <td><strong>${info.score ?? 0}</strong></td>
                <td>${(info.reasons ?? []).join(', ') || '—'}</td>
                <td>${info.ratio ?? '—'}</td>
                <td>${info.entropy ?? 0}</td>
                <td>${info.std_intervals ?? '—'}</td>
                <td>${info.max_pps ?? 0}</td>
                <td>
                    <button onclick="event.stopPropagation(); updateWhitelist('${ip}','add')">White</button><br>
                    <button onclick="event.stopPropagation(); addWatchlist('${ip}')">Watch</button><br>
                    <button onclick="event.stopPropagation(); resetIP('${ip}')">Reset</button>
                </td>
                <td>
                    <a href="https://ipinfo.io/${ip}" target="_blank">IPinfo</a><br>
                    <a href="https://www.abuseipdb.com/check/${ip}" target="_blank">AbuseIPDB</a>
                </td>
            `;
        } else if (isWatch) { // watchlist
            [ip, info] = entry;
            const ratio = `${info.ratio_current ?? '-'} / ${info.max_ratio ?? '-'}`;
            const entropy = `${info.entropy_current ?? '-'} / ${info.max_entropy ?? '-'}`;
            const std = `${info.std_current ?? '-'} / ${info.min_std ?? '-'}`;
            const pps = `${info.pps_current ?? '-'} / ${info.max_pps ?? '-'}`;
            
             // display the IP, ratio, entropy, std intervals and max PPS for each entry in the watchlist overview, along with an action button to remove from watchlist, and a click event on the row to show the dropdown with detailed metrics (same as graylist)
            tr.innerHTML = `
                <td><code>${ip}</code></td>
                <td>${ratio}</td>
                <td>${entropy}</td>
                <td>${std}</td>
                <td>${pps}</td>
                <td>
                    <button onclick="event.stopPropagation(); removeWatchlist('${ip}')">Remove</button><br>
                    <button onclick="event.stopPropagation(); resetIP('${ip}')">Reset</button>
                </td>
            `;
        } else { // whitelist
            ip = entry;
            tr.innerHTML = `
                <td><code>${ip}</code></td>
                <td>
                    <button onclick="event.stopPropagation(); updateWhitelist('${ip}','remove')">Remove</button>
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
                    openDropdowns[kind] = openDropdowns[kind].filter(x => x !== ip);
                    return;
                }

                const dropdown = document.createElement('tr');
                dropdown.classList.add(`${kind}-dropdown`);
                const td = document.createElement('td');
                td.colSpan = tr.children.length;

                const metricNames = { // human-readable names for the metrics to display in the dropdown
                    max_ratio: "SYN/ACK",
                    max_entropy: "Port entropy",
                    min_std: "Std Δt",
                    max_pps: "Max PPS"
                };

                let html = `<table style="width:100%; margin-top:5px;">
                    <thead><tr><th>Metric</th><th>Value</th><th>Last updated</th></tr></thead><tbody>`;

                const metricOrder = [ // order of metrics to display in the dropdown
                    "max_ratio",
                    "max_entropy",
                    "min_std",
                    "max_pps"
                ];

                metricOrder.forEach(metric => { // for each metric, get the display value and last updated time, then add a row to the dropdown table with this information
                    const value = getMetricValueDisplay(info, metric);
                    const lastUpdated = info.last_updated?.[metric] 
                                        ? new Date(info.last_updated[metric]*1000).toLocaleString() 
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

                if (!openDropdowns[isGray ? 'graylist' : 'watchlist'].includes(ip)) // add the IP to the list of open dropdowns for the respective list type, so that it can be reopened after a refresh if it was open before
                    openDropdowns[isGray ? 'graylist' : 'watchlist'].push(ip);
            });
        }
    });

    if (!isGray && !isWatch) { // if it's whitelist, we don't have dropdowns, so we can just return after rendering
        window.scrollTo(0, scrollY);
        return;
    }

    const kind = isGray ? 'graylist' : 'watchlist';

    openDropdowns[kind].forEach(ip => { // after rendering the list, we check which dropdowns were open before the refresh and we try to reopen them by simulating a click on the respective row, so that the user doesn't lose the context of which entries they were inspecting in detail when the list refreshes
        const rows = Array.from(containerBody.querySelectorAll('tr'));
        for (const row of rows) {
            const ipRow = row.querySelector('td code')?.textContent;
            if (ipRow === ip) {
                row.click();
                break;
            }
        }
    });

    window.scrollTo(0, scrollY); // restore scroll position after rendering, so that the user doesn't lose their place in the list when it refreshes
}

function getMetricValueDisplay(info, metric) { // get the display value for a specific metric based on the info object for an IP entry, formatting it in a human-readable way depending on the type of metric (e.g., showing SYN/ACK counts for max_ratio, listing ports for max_entropy, showing mean interval for min_std, and showing 95th percentile window and packet count for max_pps), so that it can be easily understood by the user when viewing the dropdown with detailed metrics for each entry in the graylist or watchlist
    switch(metric) {
        case 'max_ratio': // SYN/ACK
            return `SYN: ${info.syn_count || 0} / ACK: ${info.ack_count || 0}`;
        case 'max_entropy': // Port entropy
        if (info.used_ports && info.used_ports.length) {
            const portsWithNames = info.used_ports.map(p => {
                const n = parseInt(p, 10);
                return COMMON_PORTS[n] ? `${n} (${COMMON_PORTS[n]})` : `${n}`;
            });

            return `Ports: ${portsWithNames.join(', ')}`;
        } else {
            return `Ports: -`;
        }
        case 'min_std': // Intervals
            return `Mean: ${info.mean_intervals || '-'}`;
        case 'max_pps': // PPS
            return `95th percentile window: ${info.p95_window || '-'} s | Packets: ${info.packet_count || '-'}`;
        default:
            return '-';
    }
}

async function refreshGraylist() { // refresh graylist data by reloading from server and rendering in the table
    await loadPenaltiesAndMaxScore();
    try {
        const data = await fetchJson('/api/graylist'); // fetch graylist data from server
        renderList({ // render graylist overview
            containerBody: graylistBody,
            emptyContainer: graylistEmpty,
            items: data || {},
            type: 'graylist'
        });
        renderList({ // render graylist lists
            containerBody: listsGraylistBody,
            emptyContainer: listsGraylistEmpty,
            items: data || {},
            type: 'graylist'
        });
    } catch (err) {
        showError('Error in graylist: ' + err.message);
    }
}

async function refreshWatchlist() { // refresh watchlist data by reloading from server and rendering in the tables
    try {
        const data = await fetchJson('/api/watchlist'); // fetch watchlist data from server

        watchlistBody.innerHTML = ''; // clear previous data
        renderList({ // render watchlist overview
            containerBody: watchlistBody,
            emptyContainer: watchlistEmpty,
            items: data || {},
            type: 'watchlist'
        });

        listsWatchlistBody.innerHTML = ''; // clear previous data
        renderList({ // render watchlist lists
            containerBody: listsWatchlistBody,
            emptyContainer: listsWatchlistEmpty,
            items: data || {},
            type: 'watchlist'
        });

    } catch (err) {
        showError('Error in watchlist: ' + err.message);
    }
}

async function refreshWhitelist() { // refresh whitelist data by reloading from server and rendering in the table
    try {
        const data = await fetchJson('/api/whitelist'); // fetch whitelist data from server
        renderList({ // render whitelist lists
            containerBody: listsWhitelistBody,
            emptyContainer: listsWhitelistEmpty,
            items: data || [],
            type: 'whitelist'
        });
    } catch (err) {
        showError('Error in whitelist: ' + err.message);
    }
}

async function resetIP(ip) { // "pardon" an IP in the graylist by sending a request to the server, then refresh all relevant data
    try {
        await fetch('/api/reset', { // send reset request to server for the given IP
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
        await fetch('/api/watchlist/add', { // send add request to server for the given IP
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
        await fetch('/api/watchlist/remove', { // send remove request to server for the given IP
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
        await fetch(`/api/whitelist/${action}`, { // send add/remove request to server for the given IP based on the specified action
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        await Promise.all([refreshStats(), refreshGraylist(), refreshWhitelist()]); // refresh all relevant data after updating the whitelist
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
    const res = await fetch('/api/thresholds'); // fetch current threshold settings from server
    const data = await res.json();

    for (const key in data) { // populate form inputs with current settings values
      const input = document.getElementById(key);
      if (input) input.value = data[key];
    }

    settingsStatus.textContent = ''; // clear any previous status messages
  } catch(err) { 
        showError("Error in settings: " + err.message);
    }
}

async function loadPenalties() { // fetch current penalties settings from server and populate the form inputs
  try {
    const res = await fetch('/api/penalties'); // fetch current penalties settings from server
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

settingsForm.addEventListener('submit', async (e) => { // handle settings form submission by sending updated values to the server, then show success/error message
  e.preventDefault(); // prevent default form submission behavior

  const formData = new FormData(settingsForm); // extract form data into an object to send to the server
  const payload = {};
  formData.forEach((v, k) => payload[k] = parseFloat(v));

  try {
    const res = await fetch('/api/thresholds', { // send updated settings to server
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Errore salvataggio');

    // if settings are updated successfully, show success message with timestamp
    const ts = new Date().toLocaleString();
    settingsStatus.textContent = `Settings saved! ${ts}`;
    settingsStatus.style.color = 'green';
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
    if (!res.ok) throw new Error('Errore salvataggio');

    // if penalties are updated successfully, show success message with timestamp and refresh all relevant data to reflect new penalties
    const ts = new Date().toLocaleString();
    penaltiesStatus.textContent = `Settings saved! ${ts}`;
    penaltiesStatus.style.color = 'green';

    await Promise.all([refreshStats(), refreshGraylist(), refreshWhitelist(), refreshWatchlist()]);
  } catch (err) {
    showError('Error in penalties: ' + err.message);
  }
});


/// THEME TOGGLE and LOGOUT
const savedTheme = localStorage.getItem('theme'); // check if user has a saved theme preference in localStorage
if (savedTheme === 'dark' || (!savedTheme && prefersDark)) { // if saved preference is dark or no preference but system prefers dark, enable dark theme by default
  document.body.classList.add('dark-theme');
  toggleBtn.textContent = '☀️';
}

toggleBtn.addEventListener('click', () => { // toggle between light and dark themes when the theme toggle button is clicked, save the preference in localStorage, and update chart colors to match the theme
  const isDark = document.body.classList.toggle('dark-theme');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  toggleBtn.textContent = isDark ? 'Light ☀️' : 'Dark 🌙';
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

    // initial refresh of all data to populate the UI on page load
    await refreshStats();
    await refreshGraylist();
    await refreshWatchlist();
    await refreshWhitelist();
    await refreshHosts();

    // auto-refresh
    setInterval(refreshStats, CAPTURE_DURATION*1000);
    setInterval(refreshGraylist, CAPTURE_DURATION*1000);
    setInterval(refreshWatchlist, CAPTURE_DURATION*1000);
    setInterval(refreshWhitelist, CAPTURE_DURATION*1000);
    setInterval(refreshHosts, 60*1000);
}

init(); // start the application by initializing everything on page load