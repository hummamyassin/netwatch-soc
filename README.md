# NetWatch SOC: Network Security Monitor & Incident Dashboard

A beginner-friendly network security monitoring project. NetWatch SOC reads
**recorded** network traffic (PCAP files), turns it into structured logs,
runs simple, explainable detection rules over those logs, and shows the
resulting alerts in a SOC-style dashboard.

It is built step by step as a learning and portfolio project for Junior SOC
Analyst, Cybersecurity Trainee, IT Security and Networking roles.

```
PCAP ──► Wireshark / Zeek ──► Structured logs ──► Python detection rules ──► Alerts ──► Streamlit dashboard
```

> **Scope:** NetWatch SOC only analyses capture files you already have. It does
> not capture live traffic, scan networks, or generate attacks.

---

## Objectives

- Learn how network traffic looks at the packet level (Wireshark / TShark).
- Learn how a network security monitor (Zeek) summarises traffic into logs.
- Analyse those logs with Python and pandas.
- Write **deterministic** detection rules: the same input always gives the
  same alert, and every alert can be explained.
- Present alerts in a dashboard and practise an analyst's investigation workflow.

## Current capabilities (Milestones 1–5)

- `netwatch/pcap_inspect.py`: prints a readable preview of the first packets
  in a `.pcap` / `.pcapng` file: time, source/destination IP, protocol,
  ports and length. It uses the `tshark` program that ships with Wireshark.
- `netwatch/zeek_conn.py`: reads a Zeek `conn.log` in either **TSV** or
  **JSON** format and turns every connection into the same clean Python
  record (real timestamps, validated IPs, numbers instead of strings, `None`
  for missing values). Bad lines are skipped and reported with their line
  number. Includes a small CLI preview.
- `netwatch/analyzer.py`: loads connections into a **pandas** DataFrame and
  summarises them: totals, unique IPs, protocol mix, top sources, top
  destination ports, connection states, bytes, durations and connections
  over time. Missing values are never counted as zero.
- `netwatch/detection.py`: four deterministic, explainable detection rules
  (possible port scan, high connection rate, watchlisted destination port,
  repeated failed connections) that produce alerts with stable IDs, severity,
  thresholds, explanations and supporting connection references.
- A synthetic demo dataset in `data/demo/` (450 connections, TSV and JSON)
  and synthetic test fixtures in `tests/fixtures/zeek/`, so everything can be
  tried and tested without real captures or Zeek.
- `dashboard.py`: a dark SOC-style **Streamlit** dashboard with KPI cards,
  Plotly charts and a filterable alerts table. It uses the real analyzer and
  detection engine on the demo data or on an uploaded Zeek log.
- Unit tests for all tools, plus headless UI tests for the dashboard.

The alert investigation workflow is not built yet. See the roadmap.

## Roadmap

| # | Milestone | What gets built / learned |
|---|-----------|---------------------------|
| 1 | **Networking, PCAP, Wireshark** ✅ | Project setup; read packets from a capture with TShark |
| 2 | **Zeek logs** ✅ | Parse Zeek `conn.log` (TSV and JSON) into normalised connection records |
| 3 | **Python log analysis** ✅ | Load Zeek logs into pandas, summarise hosts, ports, protocols, states, bytes, time |
| 4 | **Deterministic detection rules** ✅ | Port scan, connection rate, watchlisted ports, repeated failures; explainable alerts |
| 5 | **Streamlit SOC dashboard** ✅ | KPI cards, Plotly charts, alerts table with filters, uploads, detection settings |
| 6 | Alert investigation workflow | Drill into an alert, see related connections, mark status |
| 7 | Optional AI explanations | Gemini API *explains* an existing alert. It never decides what is an alert |
| 8 | Testing and GitHub polish | More tests, screenshots, clean README, demo data |

---

## Setup

### 1. Python

You need Python 3.10 or newer. Check with:

```bash
python --version
```

Create a virtual environment (an isolated folder for this project's
packages, so nothing is installed into your system Python), then install
the packages from `requirements.txt` into it:

```bash
python -m venv .venv
```

```bash
.venv\Scripts\python -m pip install -r requirements.txt
```

On macOS/Linux use `.venv/bin/python` instead of `.venv\Scripts\python`.
You can also activate the environment (`.venv\Scripts\Activate.ps1` in
PowerShell, `source .venv/bin/activate` on macOS/Linux) and then simply type
`python`. The commands below assume an activated environment.

### 2. Wireshark and TShark

- **Wireshark** is the graphical program for looking at packets.
- **TShark** is its command-line version. This project calls TShark from Python.

**Windows**

1. Download the installer from <https://www.wireshark.org/download.html>.
2. During install, keep the **TShark** component ticked (it is by default).
3. **Npcap** is only needed to capture live traffic. This project only reads
   files, so you can skip it.
4. The installer usually does not add TShark to `PATH`. The script also checks
   `C:\Program Files\Wireshark\tshark.exe` automatically. To use `tshark`
   in your own terminal, add `C:\Program Files\Wireshark` to your `PATH`.

Or install from the command line with winget:

```bash
winget install WiresharkFoundation.Wireshark
```

**Ubuntu / Debian.** TShark is a separate package:

```bash
sudo apt install tshark
```

If it asks whether non-superusers should be able to capture packets, answer
**No**. Reading files does not need it.

**macOS**

```bash
brew install wireshark
```

**Check it works:**

```bash
tshark --version
```

### 3. Get a training capture (PCAP)

Only use captures from trusted, legitimate training sources. **Never commit
capture files to Git.** They can contain private data. The `.gitignore`
already blocks `*.pcap` and `*.pcapng`.

Good starting points:

- **Wireshark Sample Captures**: <https://wiki.wireshark.org/SampleCaptures>.
  Small, well-labelled captures of normal protocols (HTTP, DNS, DHCP, …).
  Start here.
- **Netresec, Publicly available PCAP files**:
  <https://www.netresec.com/?page=PcapFiles>. A curated list of larger
  datasets for later milestones.
- **Malware-Traffic-Analysis.net**: real malware traffic for later practice.
  The ZIPs are password-protected because they can contain live malware.
  Only extract them inside an isolated lab VM, and only after you are
  comfortable with the basics.

Save files into `data/pcaps/`. That folder is ignored by Git.

---

## Usage

Run from the project folder:

```bash
python -m netwatch.pcap_inspect data/pcaps/http.cap
```

Show more or fewer packets with `--limit` (1–1000, default 20):

```bash
python -m netwatch.pcap_inspect data/pcaps/http.cap --limit 5
```

Help:

```bash
python -m netwatch.pcap_inspect --help
```

### Understanding the output

Example (illustrative):

```
File: C:\...\data\pcaps\http.cap
Showing 3 packet(s) (limit 3)

   #  Time                         Source                  Destination             Protocol    SrcPort  DstPort  Length
-----------------------------------------------------------------------------------------------------------------------
   1  2004-05-13 10:17:07.311 UTC  145.254.160.237         65.208.228.223          TCP            3372       80      62
   2  2004-05-13 10:17:08.222 UTC  65.208.228.223          145.254.160.237         TCP              80     3372      62
   3  2004-05-13 10:17:08.222 UTC  145.254.160.237         65.208.228.223          TCP            3372       80      54
```

| Column | Meaning |
|--------|---------|
| `#` | Packet number in this preview |
| `Time` | When the packet was recorded, in UTC |
| `Source` / `Destination` | IPv4 or IPv6 address that sent / received the packet |
| `Protocol` | Highest protocol layer TShark recognised (e.g. `TCP`, `DNS`, `HTTP`, `ARP`). Unidentified payload (`data`) is skipped, as in Wireshark |
| `SrcPort` / `DstPort` | TCP or UDP port. Well-known ports identify services (80 = HTTP, 443 = HTTPS, 53 = DNS) |
| `Length` | Size of the whole packet on the wire, in bytes |

A `-` means the field doesn't apply to that packet. For example, ICMP (ping)
has no ports, and ARP has no IP addresses.

Exit codes: `0` success, `1` a clear error (file missing, TShark missing,
unreadable file), `2` invalid command-line arguments.

---

## Zeek conn.log parser (Milestone 2)

### What Zeek and conn.log are

**Zeek** is an open-source network security monitor. Instead of showing every
packet like Wireshark, it groups packets into **connections** and writes
summary logs. `conn.log` has one line per connection: who talked to whom, on
which port and protocol, for how long, how much data moved, and how the
connection ended. SOC analysts read these logs far more often than raw packets.

### Try it now (no Zeek needed)

The repository includes two small synthetic logs:

```bash
python -m netwatch.zeek_conn tests/fixtures/zeek/conn_tsv.log
```

```bash
python -m netwatch.zeek_conn tests/fixtures/zeek/conn_json.log --limit 3
```

Output:

```
File:    C:\...\tests\fixtures\zeek\conn_tsv.log
Format:  Zeek TSV
Parsed:  6 connection(s), 0 line(s) skipped
Showing: 6 of 6

   #  Time (UTC)               Proto  Source                  Destination             Service    Duration  OrigBytes  RespBytes  OrigPkts  RespPkts  State
-----------------------------------------------------------------------------------------------------------------------------------------------------------
   1  2023-11-14 22:13:20.000  tcp    192.0.2.10:49152        198.51.100.20:80        http          1.250        512       2048         8         7  SF
   2  2023-11-14 22:13:21.500  udp    192.0.2.10:53001        192.0.2.53:53           dns           0.020         40        120         1         1  SF
   3  2023-11-14 22:13:22.250  tcp    192.0.2.10:49153        203.0.113.5:22          -                 -          -          -         1         0  S0
   4  2023-11-14 22:13:23.000  tcp    192.0.2.10:49154        203.0.113.5:23          -             0.001          0          0         1         1  REJ
   5  2023-11-14 22:13:24.000  icmp   192.0.2.10              198.51.100.20           -             0.030         56         56         1         1  OTH
   6  2023-11-14 22:13:25.750  udp    [2001:db8::10]:5353     [2001:db8::fb]:5353     dns           0.100         60          0         1         0  S0

Connection states shown above:
  OTH     No SYN seen (midstream traffic or not TCP)
  REJ     Attempt rejected
  S0      Attempt seen, no reply
  SF      Normal setup and close
```

### Reading the output

| Column | Zeek field | Meaning |
|--------|-----------|---------|
| `Time (UTC)` | `ts` | When the connection started |
| `Proto` | `proto` | Transport protocol: `tcp`, `udp` or `icmp` |
| `Source` | `id.orig_h` / `id.orig_p` | The **originator**, the side that started the connection |
| `Destination` | `id.resp_h` / `id.resp_p` | The **responder** |
| `Service` | `service` | Application protocol Zeek recognised (`http`, `dns`, `ssl`, …) |
| `Duration` | `duration` | Seconds from first to last packet |
| `OrigBytes` / `RespBytes` | `orig_bytes` / `resp_bytes` | Payload bytes sent by each side |
| `OrigPkts` / `RespPkts` | `orig_pkts` / `resp_pkts` | Packets sent by each side |
| `State` | `conn_state` | How the connection went (see below) |

`-` means Zeek did not record that value. For example, an `S0` connection got
no reply, so it has no duration or byte counts. ICMP has no ports. Zeek stores
the ICMP type/code in the port columns, and the parser moves them to separate
`icmp_type` / `icmp_code` fields so they are never mistaken for ports.

Common connection states:

| State | Meaning | Why an analyst cares |
|-------|---------|----------------------|
| `SF` | Normal setup and close | Ordinary, completed traffic |
| `S0` | Attempt seen, no reply | Many of these can mean scanning or a dead host |
| `REJ` | Attempt rejected | The port is closed. Many in a row can mean scanning |
| `RSTO` / `RSTR` | One side reset the connection | Aborted connections |
| `OTH` | No TCP handshake seen | Midstream captures, ICMP, odd traffic |

The full list is in `CONN_STATES` in `netwatch/zeek_conn.py`.

### Using the parser from Python

```python
from netwatch.zeek_conn import parse_conn_log

result = parse_conn_log("tests/fixtures/zeek/conn_tsv.log")
print(result.log_format)             # "tsv"
for conn in result.records:          # list of ConnRecord
    print(conn.src_ip, conn.dst_port, conn.conn_state)
print(result.errors)                 # e.g. ["line 12: field 'orig_bytes': not a whole number: 'x'"]
```

- **Bad lines** (invalid IP, wrong column count, non-numeric bytes, broken
  JSON) are skipped and listed in `result.errors`, and the good lines are
  still returned.
- **Whole-file problems** raise `ZeekLogError`. Examples: the file is
  missing or empty, the format is unknown, it has no `#fields` header, or it
  is a different log such as `dns.log`.
- CLI exit codes: `0` connections parsed (even if some lines were skipped),
  `1` file error or no valid connections, `2` invalid arguments.

### Generating a real conn.log later (optional)

You don't need Zeek for this milestone. When you want real logs:

- Zeek has **no official native Windows build**. On Windows, use **WSL2**
  (Ubuntu) or a Linux VM. Install instructions:
  <https://docs.zeek.org/en/master/install.html>
- Run Zeek on a training PCAP inside an empty folder:

  ```bash
  zeek -C -r http.cap
  ```

  `-r` reads a file (no live capture) and `-C` ignores bad checksums, which
  are common in captures. Zeek writes `conn.log`, `dns.log`, `http.log`, …
  into the current folder.
- For JSON output instead of TSV:

  ```bash
  zeek -C -r http.cap LogAscii::use_json=T
  ```

Keep real logs in `data/zeek_logs/`. Git ignores that folder.

Text fields (`uid`, `proto`, `service`, `conn_state`, `history`) may only
contain the characters Zeek itself writes. A line with anything else (for
example terminal escape codes or Markdown links) is skipped and reported,
so hostile values never reach reports or the dashboard.

---

## Traffic analysis with pandas (Milestone 3)

`netwatch/analyzer.py` turns the parsed connections into a pandas
**DataFrame** (a table with typed columns) and answers the first questions an
analyst asks about a log: how much traffic, between whom, on which ports,
and how did the connections end?

```bash
python -m netwatch.analyzer tests/fixtures/zeek/conn_tsv.log --top 5
```

Output (shortened):

```
Connections:     6 (0 line(s) skipped, 0 duplicate(s) removed)
Time range:      2023-11-14 22:13:20 UTC -> 2023-11-14 22:13:25 UTC (5.8 s)
Source IPs:      2 unique
Destination IPs: 4 unique
Bytes sent:      668 B by originators (5 of 6 connections recorded), 2.2 KB by responders (5 of 6 recorded)
Avg duration:    0.280 s (5 of 6 connections recorded)

Protocols
proto  connections  percent
  tcp            3     50.0
  udp            2     33.3
 icmp            1     16.7
...
```

| Function | Answers |
|----------|---------|
| `total_connections`, `unique_source_ips`, `unique_destination_ips` | How big is the log, how many hosts are involved? |
| `protocol_distribution` | TCP vs UDP vs ICMP mix, with percentages |
| `top_source_ips` | Which hosts started the most connections? |
| `top_destination_ports` | Which services were contacted most? Counted per protocol (`53/udp` ≠ `53/tcp`) |
| `connection_state_distribution` | How did connections end (`SF`, `S0`, `REJ`, ...)? |
| `byte_totals`, `duration_stats` | How much data moved, how long connections lasted |
| `connections_over_time` | Activity per time bucket (UTC), with quiet periods shown as 0 |

Design rules:

- **Missing is not zero.** A connection without a byte count is left out of
  the byte total, and the report says how many connections were included
  ("5 of 6 recorded").
- **UTC everywhere.** All timestamps are stored as UTC.
- **Deterministic order.** Ties in top-N tables are broken by IP address
  (numerically) or port number, so the same log always gives the same table.
- **No double counting.** A connection that appears twice (same Zeek `uid`,
  for example a log appended to itself) is counted once and reported as a
  removed duplicate.
- **One shape for both formats.** TSV and JSON logs produce identical DataFrames.

---

## Detection rules (Milestone 4)

`netwatch/detection.py` turns connections into **alerts** using four simple,
deterministic rules. The same log with the same settings always gives the
same alerts with the same IDs, and every alert explains itself from the data
and the thresholds. No AI is involved in deciding what is an alert.

| ID | Alert type | Triggers when (default settings) | Base severity |
|----|------------|----------------------------------|---------------|
| NW-001 | Possible Port Scan | one source contacts ≥ 15 distinct ports on the same host within 60 s | Medium |
| NW-002 | High Connection Rate | one source starts ≥ 100 connections within 60 s | Low |
| NW-003 | Suspicious Destination Port | traffic reaches a watchlisted port (23, 3389, 4444, 5900, 6667, 31337) | Low |
| NW-004 | Repeated Failed Connections | ≥ 10 rejected/unanswered TCP attempts to the same service within 60 s | Medium |

Severity goes up one level when the measured value is at least 3 × the
threshold. **Alerts describe possible suspicious behaviour, not confirmed
attacks**, and each rule has documented false positives. The full reference
(windows, failed states, severity, tuning, false positives) is in
[docs/DETECTION_RULES.md](docs/DETECTION_RULES.md).

Try it on the synthetic demo data:

```bash
python -m netwatch.detection data/demo/conn_demo.log
```

```
Alerts:  6 (High 2, Medium 1, Low 3)

[2] HIGH   NW-001 Possible Port Scan   (NW-001-a9bbeb729a3d)
    Source:       203.0.113.66
    Destination:  192.0.2.20
    Protocol:     tcp   Ports (60): 1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88 ...
    Seen:         2025-03-10 08:20:00 UTC -> 2025-03-10 08:20:23 UTC (60 connection(s))
    Measured:     60 (threshold 15, window 60 s)
    Why:          203.0.113.66 contacted 60 different TCP ports on 192.0.2.20 within 60 s ...
```

Change thresholds or pick rules from the command line:

```bash
python -m netwatch.detection data/demo/conn_demo.log --scan-ports 50 --rules NW-001,NW-004
```

With 50 instead of 15 ports the scan alert is still raised, but as Medium
instead of High (60 ports is no longer ≥ 3 × the threshold).

The demo dataset and what it contains are described in
[data/demo/README.md](data/demo/README.md). It is made by
`scripts/generate_demo_data.py` (fixed seed, documentation IPs only).

---

## SOC dashboard (Milestone 5)

Start the dashboard from the project folder (virtual environment active):

```bash
streamlit run dashboard.py
```

Your browser opens <http://localhost:8501>. Press `Ctrl+C` in the terminal to stop it.

What you get:

- **Sidebar:** the demo dataset (TSV or JSON) or your own Zeek `conn.log`
  upload, detection settings for every rule (applied with one button), and
  navigation.
- **KPI cards:** total connections, unique source/destination IPs, total
  alerts and alerts per severity.
- **Network analysis:** connections over time, top source IPs, top
  destination ports, TCP vs UDP distribution, connection states.
- **Security alerts:** a table with severity, status, type, source,
  destination, ports, first/last seen (UTC) and connection count, filterable
  by severity, type and status.

Everything on screen is computed by the tested `netwatch` package. The UI
file contains no detection or analysis logic. Results are cached, so
changing a filter does not re-parse the log or re-run detection.

**Uploads:** `.log`, `.json`, `.tsv` or `.txt`, up to 20 MB. Files are parsed
in memory and never saved or executed. Binary files (for example a PCAP
uploaded by mistake) are refused with a helpful message, and empty or
malformed logs show clear errors instead of crashing.

**Privacy settings** (`.streamlit/config.toml`): the app only listens on
`localhost` (other computers on your network cannot open it), and
Streamlit's usage statistics are turned off.

## Running the tests

```bash
python -m unittest -v
```

The tests don't need TShark or Zeek. One extra test reads a tiny synthetic
capture with real TShark. It is skipped automatically when TShark isn't
installed. The dashboard tests use Streamlit's `AppTest` to run
`dashboard.py` without a browser, including simulated uploads.

## Safety

- Reads files only: no live capture, no scanning, no traffic generation.
- `tshark` runs with `-n`, so no DNS lookups are made while reading a capture.
- TShark runs from an argument list (no shell), so file names can't inject commands.
- Packet and log contents are only ever parsed and displayed, never executed.
- Keep Wireshark updated. Its parsers process untrusted data.

## Project structure

```
netwatch/            Python package
  pcap_inspect.py    Milestone 1: PCAP preview tool
  zeek_conn.py       Milestone 2: Zeek conn.log parser (TSV + JSON)
  analyzer.py        Milestone 3: pandas traffic analysis
  detection.py       Milestone 4: rule-based detection engine
  dashboard_data.py  Milestone 5: data preparation for the dashboard (no UI code)
dashboard.py         Milestone 5: Streamlit user interface
.streamlit/config.toml  Dashboard settings: localhost only, no telemetry, dark theme
scripts/
  generate_demo_data.py  Rebuilds the synthetic demo dataset and fixtures
data/demo/           Synthetic demo dataset (tracked; documentation IPs only)
docs/DETECTION_RULES.md  Rule logic, severity, false positives, tuning
tests/               Unit tests (python -m unittest)
  fixtures/zeek/     Synthetic conn.log files (documentation IPs only)
docs/LEARNING_LOG.md Concepts learned, milestone by milestone
data/pcaps/          Your local capture files (ignored by Git)
CLAUDE.md            Project rules for the AI coding assistant
```
