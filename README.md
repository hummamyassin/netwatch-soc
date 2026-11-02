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

## Current capabilities (Milestone 1)

- `netwatch/pcap_inspect.py`: prints a readable preview of the first packets
  in a `.pcap` / `.pcapng` file: time, source/destination IP, protocol,
  ports and length. It uses the `tshark` program that ships with Wireshark.
- Unit tests for argument validation, parsing and error handling.

Nothing else is built yet. See the roadmap.

## Roadmap

| # | Milestone | What gets built / learned |
|---|-----------|---------------------------|
| 1 | **Networking, PCAP, Wireshark** ✅ | Project setup; read packets from a capture with TShark |
| 2 | Zeek logs | Convert PCAPs into Zeek logs (`conn.log`, `dns.log`, `http.log`, …) |
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

Milestone 1 uses only the Python standard library, so there is nothing to
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
| `Protocol` | Highest protocol layer TShark recognised (e.g. `TCP`, `DNS`, `HTTP`, `ARP`) |
| `SrcPort` / `DstPort` | TCP or UDP port. Well-known ports identify services (80 = HTTP, 443 = HTTPS, 53 = DNS) |
| `Length` | Size of the whole packet on the wire, in bytes |

A `-` means the field doesn't apply to that packet. For example, ICMP (ping)
has no ports, and ARP has no IP addresses.

Exit codes: `0` success, `1` a clear error (file missing, TShark missing,
unreadable file), `2` invalid command-line arguments.

## Running the tests

```bash
python -m unittest -v
```

The tests don't need TShark. One extra test reads a tiny synthetic capture
with real TShark. It is skipped automatically when TShark isn't installed.

## Safety

- Reads files only: no live capture, no scanning, no traffic generation.
- `tshark` runs with `-n`, so no DNS lookups are made while reading a capture.
- TShark runs from an argument list (no shell), so file names can't inject commands.
- Packet contents are only ever displayed, never executed.
- Keep Wireshark updated. Its parsers process untrusted data.

## Project structure

```
netwatch/            Python package
  pcap_inspect.py    Milestone 1: PCAP preview tool
tests/               Unit tests (python -m unittest)
docs/LEARNING_LOG.md Concepts learned, milestone by milestone
data/pcaps/          Your local capture files (ignored by Git)
CLAUDE.md            Project rules for the AI coding assistant
```
