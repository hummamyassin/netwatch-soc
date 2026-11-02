# Real PCAP lab: end-to-end validation

This lab runs NetWatch SOC on a **real, publicly published capture** instead
of the synthetic demo data:

```
PCAP -> TShark check -> Zeek conn.log -> parser -> pandas analyzer -> detection rules -> dashboard -> investigation
```

Run on 2026-11-02 against commit `0ffa32a`. Nothing in this lab captured
live traffic, scanned anything or executed packet payloads. The capture and
the Zeek logs stay out of Git (`data/pcaps/` and `data/zeek_logs/` are ignored).

## Status at a glance

| Step | Result | Evidence |
|------|--------|----------|
| Capture obtained and verified | **Verified** | SHA-256, capinfos, TShark statistics below |
| TShark / `pcap_inspect` | **Verified**, 1 bug found and fixed | 43/43 packets parsed; 42/43 identical to Wireshark on all 7 fields, 1 documented difference |
| Zeek offline conversion | **Verified** (Zeek really ran) | `conn.log` written in TSV and JSON, empty stderr |
| Parser, analyzer, detection | **Verified** | 3 connections, statistics checked by hand, 0 alerts |
| Dashboard with the real `conn.log` | **Verified headlessly** | real `dashboard.py` driven with Streamlit AppTest uploads |
| Dashboard upload in a visible browser | **Not verified by me** | the in-app browser cannot attach local files; see "Your turn" |
| Investigation workflow | **Synthetic data only** | the real capture raised no alert; workflow verified on the demo data by the test suite |

## 1. Objective

Show that the whole pipeline works on real Zeek output, not just on the
project's own synthetic logs, and record what a benign capture looks like.

## 2. Capture provenance

| Item | Value |
|------|-------|
| Name | `http.cap`, Wireshark sample "A simple HTTP request and response" |
| Listed on | <https://wiki.wireshark.org/SampleCaptures> |
| Download URL | `https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap` (redirects to the Wireshark project's GitLab wiki) |
| Stored at | `data/pcaps/http.cap` (git-ignored) |
| SHA-256 | `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d` |
| Size | 25,803 bytes, classic pcap, Ethernet |
| Packets | 43 |
| Time range | 2004-05-13 10:17:07.311224 to 10:17:37.704928 UTC (30.39 s) |

Public samples are widely used for training, but no capture can be
guaranteed harmless. It was only ever read by TShark and Zeek.

## 3. Environment

| Tool | Version |
|------|---------|
| Windows | 11 |
| WSL2 distribution | Ubuntu 26.04.1 LTS (kernel 6.18.54.1-microsoft-standard-WSL2) |
| Zeek | 8.0.11 at `/opt/zeek/bin/zeek` (inside WSL) |
| Wireshark / TShark | 4.6.9 (Windows) |
| Python | 3.12.3 with pandas 3.1.0, Streamlit 1.66.1, Plotly 7.1.0 |

## 4. TShark verification

```bash
capinfos data/pcaps/http.cap
tshark -r data/pcaps/http.cap -n -q -z io,phs -z conv,tcp -z conv,udp
python -m netwatch.pcap_inspect data/pcaps/http.cap --limit 15
```

- Protocol hierarchy: 41 TCP frames (4 carrying HTTP), 2 UDP frames (DNS).
- Conversations: two TCP connections from 145.254.160.237 to port 80
  (65.208.228.223, 34 frames; 216.239.59.99, 7 frames) and one DNS lookup
  to 145.253.2.203 (2 frames).
- `pcap_inspect` read all 43 packets. A script compared every packet's time,
  IPs, protocol, ports and length with Wireshark's own columns.

**Bug found and fixed.** Packets 27 and 38 were labelled `DATA-TEXT-LINES`
and `XML`, while Wireshark shows HTTP. Root cause: these layers describe the
*format of the HTTP body*, not a network protocol, and `top_protocol()` only
skipped the generic `data` layer. Fix: skip trailing payload-format layers
(`data`, `data-text-lines`, `media`, `xml`, `json`). A regression test covers
the exact stacks from this capture. After the fix 42/43 packets match on all
fields. Packet 38 shows `HTTP` where Wireshark writes the combined label
`HTTP/XML`, a deliberate simplification.

## 5. Zeek processing

Zeek writes its logs into the **current directory** and overwrites files with
the same name, so each run used a new temporary directory inside WSL:

```bash
wsl -d Ubuntu -- bash -lc 'D=$(mktemp -d /tmp/netwatch-lab-XXXXXX); cd "$D" && /opt/zeek/bin/zeek -C -r "/mnt/c/Users/<you>/Desktop/NetWatch SOC/data/pcaps/http.cap" && ls -l'
```

- `-r` reads a capture file (offline; no network interface is touched).
- `-C` ignores bad checksums, common in captures from machines that offload checksumming.
- A second run added `LogAscii::use_json=T` for JSON output.

**Outcome (verified):** both runs exited normally with an **empty stderr**
and wrote `conn.log`, `dns.log`, `http.log`, `files.log` and
`packet_filter.log`. The logs were copied to `data/zeek_logs/http_cap/{tsv,json}/`
(git-ignored).

## 6. The conn.log produced

Zeek wrote **3 connection records** (TSV shown, trimmed to key columns):

| Start (UTC) | Source | Destination | Proto | Service | Duration | Orig / resp bytes | Orig / resp pkts | State | History |
|---|---|---|---|---|---|---|---|---|---|
| 10:17:07.311 | 145.254.160.237:3372 | 65.208.228.223:80 | tcp | http | 30.063 s | 479 / 18,364 | 16 / 18 | SF | ShADadfF |
| 10:17:09.865 | 145.254.160.237:3009 | 145.253.2.203:53 | udp | dns | 0.361 s | 47 / 146 | 1 / 1 | SF | Dd |
| 10:17:10.296 | 145.254.160.237:3371 | 216.239.59.99:80 | tcp | (none) | 1.793 s | 721 / 1,590 | 3 / 4 | OTH | DadAt |

What this shows:

- **Packets add up.** 16+18, 1+1 and 3+4 are TShark's 34 + 2 + 7 = 43 packets.
- **`OTH` on port 3371 is correct.** Its first captured packet is ACK+PSH
  with no SYN: the TCP connection began before the capture started, so
  Zeek never saw a handshake.
- **Rows are in end-time order** (the DNS lookup is written before the HTTP
  connection that started earlier). NetWatch sorts by start time itself.
- **Zeek 8 format details.** The header has a new `ip_proto` column (6 = TCP,
  17 = UDP), and an unset `tunnel_parents` is written as `-`. The parser maps
  columns by name, so both were handled. A new regression test pins this layout.
- **TSV vs JSON.** Both formats give identical values on 13 compared fields.
  Durations differ by under 0.2 µs because TSV rounds to 6 decimals. Zeek
  generates new random uids on every run, so the two files have different uids.

## 7. Analyzer results (verified)

```bash
python -m netwatch.analyzer data/zeek_logs/http_cap/tsv/conn.log
```

| Statistic | Value | Checked by hand |
|-----------|-------|-----------------|
| Connections | 3 (0 lines skipped, 0 duplicates) | matches TShark's 3 conversations |
| Time range | 10:17:07 to 10:17:10 UTC (start times) | first start = first packet |
| Unique source / destination IPs | 1 / 3 | |
| Protocols | tcp 2 (66.7 %), udp 1 (33.3 %) | |
| Top destination ports | 80/tcp (2), 53/udp (1) | |
| Connection states | SF 2, OTH 1 | |
| Bytes | 1.2 KB from originators, 19.6 KB from responders (3 of 3 recorded) | 47+721+479 = 1,247 B; 146+1,590+18,364 = 20,100 B |
| Average duration | 10.739 s (3 of 3 recorded) | (0.360518 + 1.792577 + 30.063228) / 3 |

Timestamps are stored as `datetime64[us, UTC]`. No values were missing in
this capture, so the "missing is not zero" paths were not exercised here
(they are covered by the unit tests).

## 8. Detection results (verified): 0 alerts

```bash
python -m netwatch.detection data/zeek_logs/http_cap/tsv/conn.log
python -m netwatch.detection data/zeek_logs/http_cap/json/conn.log
```

Both formats: **0 alerts (High 0, Medium 0, Low 0)** with the default settings.
This is the correct result for three ordinary connections:

| Rule | Why it did not fire |
|------|---------------------|
| NW-001 Possible Port Scan | the host contacted 1 port per destination; threshold 15 distinct ports |
| NW-002 High Connection Rate | 3 connections in 3 s; threshold 100 within 60 s |
| NW-003 Suspicious Destination Port | ports 80 and 53 are not on the watchlist |
| NW-004 Repeated Failed Connections | no failed TCP states (S0/REJ/RSTOS0/SH); `OTH` is not a failure |

No threshold was lowered to produce alerts.

## 9. Dashboard verification

The real `dashboard.py` was run headlessly with Streamlit's `AppTest`, which
executes the same upload path as the browser: file check, in-memory parsing,
analyzer and detection.

| Check | TSV upload | JSON upload |
|-------|-----------|-------------|
| Accepted, no exceptions, errors or warnings | yes | yes |
| Context line | "Zeek TSV, 3 connections, 2004-05-13 10:17:07 UTC to 10:17:10 UTC" | same, "Zeek JSON" |
| KPIs | 3 connections, 1 source IP, 3 destination IPs, 0 alerts | same |
| Charts rendered | 5 | 5 |
| Zero-alert state | "No alerts for this log" shown | same |
| Investigation page | opens; "Nothing to investigate" shown | same |

**Synthetic demonstration (not real data):** because the real capture raised
no alert, the investigation workflow (start, note, close with a
disposition, status in the queue) was verified on the synthetic demo dataset
by the automated tests.

## 10. Limitations observed

- **One small capture.** Three connections from 2004 exercise parsing and the
  zero-alert path but not the detection rules. A capture with scanning or
  repeated failures would be needed to see a real alert.
- **Only conn.log is analysed.** Zeek also wrote `dns.log` and `http.log`.
  NetWatch does not read them yet.
- **Different uids per Zeek run.** Converting the same PCAP twice gives new
  uids, so alert IDs (which use uids) differ between conversions of the same capture.
- **Browser upload not exercised by me.** The headless test runs the same
  code, but a visible upload in a real browser is left for you to confirm.
- **Tooling note.** Piping a script from PowerShell into `wsl bash -s` added a
  byte-order mark, so the script's first line (`set -euo pipefail`) did not
  run. Zeek was unaffected. The reproduction command above avoids piping.

## 11. Reproduce it

1. Put the capture in `data/pcaps/` and check its hash:
   `certutil -hashfile data\pcaps\http.cap SHA256`
2. Run Zeek in a fresh directory (command in section 5) and copy `conn.log` to `data/zeek_logs/`.
3. `python -m netwatch.analyzer data/zeek_logs/http_cap/tsv/conn.log`
4. `python -m netwatch.detection data/zeek_logs/http_cap/tsv/conn.log`
5. `streamlit run dashboard.py`, choose **Upload a log**, select the `conn.log`.

### Your turn

Open <http://localhost:8501>, choose **Upload a log** and pick
`data/zeek_logs/http_cap/tsv/conn.log`. You should see 3 connections, 1 source
IP, 3 destination IPs and the "No alerts for this log" panel.

## 12. Glossary

| Term | Meaning |
|------|---------|
| PCAP | A file of recorded network packets with timestamps |
| TShark | Wireshark's command-line tool. Here it reads the capture and prints fields and statistics |
| Zeek | A network security monitor that turns packets into structured logs |
| Offline mode (`-r`) | Zeek reads a file instead of listening on a network interface |
| conn.log | Zeek's log of connections: one line per conversation between two endpoints |
| uid | Zeek's random ID for a connection, shared across its logs (conn, dns, http) |
| conn_state | How a connection went: SF normal, S0 no reply, REJ rejected, OTH no handshake seen |
| history | Letters for what Zeek saw: S SYN, h SYN-ACK, A ACK, D/d data, F/f FIN (uppercase = originator) |
| False positive / zero alerts | An alert on harmless traffic / no rule reached its threshold, the expected result for benign traffic |
| SHA-256 | A fingerprint of a file: if one byte changes, the hash changes, so it proves which file was used |
