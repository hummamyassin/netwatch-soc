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

## Current capabilities (Milestones 1–2)

- `netwatch/pcap_inspect.py`: prints a readable preview of the first packets
  in a `.pcap` / `.pcapng` file: time, source/destination IP, protocol,
  ports and length. It uses the `tshark` program that ships with Wireshark.
- `netwatch/zeek_conn.py`: reads a Zeek `conn.log` in either **TSV** or
  **JSON** format and turns every connection into the same clean Python
  record (real timestamps, validated IPs, numbers instead of strings, `None`
  for missing values). Bad lines are skipped and reported with their line
  number. Includes a small CLI preview.
- Synthetic Zeek fixtures in `tests/fixtures/zeek/`, so everything can be
  tested without installing Zeek.
- Unit tests for both tools.

Detection rules and the dashboard are not built yet. See the roadmap.

## Roadmap

| # | Milestone | What gets built / learned |
|---|-----------|---------------------------|
| 1 | **Networking, PCAP, Wireshark** ✅ | Project setup; read packets from a capture with TShark |
| 2 | **Zeek logs** ✅ | Parse Zeek `conn.log` (TSV and JSON) into normalised connection records |
| 3 | Python log analysis | Load Zeek logs into pandas, summarise hosts, ports, protocols |
| 4 | Deterministic detection rules | Simple rules, e.g. many ports from one host, rare DNS, odd connections |
| 5 | Streamlit SOC dashboard | Alerts table, charts (Plotly), filters |
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

Milestones 1–2 use only the Python standard library, so there is nothing to
`pip install` yet. Optionally create a virtual environment (an isolated
folder for this project's packages) for later milestones:

```bash
python -m venv .venv
```

Activate it on Windows (PowerShell) with `.venv\Scripts\Activate.ps1`, or
on macOS/Linux with `source .venv/bin/activate`.

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

## Running the tests

```bash
python -m unittest -v
```

The tests don't need TShark or Zeek. One extra test reads a tiny synthetic
capture with real TShark. It is skipped automatically when TShark isn't
installed.

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
tests/               Unit tests (python -m unittest)
  fixtures/zeek/     Synthetic conn.log files (documentation IPs only)
docs/LEARNING_LOG.md Concepts learned, milestone by milestone
data/pcaps/          Your local capture files (ignored by Git)
CLAUDE.md            Project rules for the AI coding assistant
```
