# Command-line guide

NetWatch SOC has four small command-line tools. Each one is a stage of the
pipeline and can be run on its own. All commands below are run from the
project folder with the virtual environment active (see the README's Quick start).

| Tool | Input | What it shows |
|------|-------|---------------|
| `python -m netwatch.pcap_inspect` | PCAP / PCAPNG | A packet-by-packet preview (needs TShark) |
| `python -m netwatch.zeek_conn` | Zeek `conn.log` | The parsed connections |
| `python -m netwatch.analyzer` | Zeek `conn.log` | A traffic summary (pandas) |
| `python -m netwatch.detection` | Zeek `conn.log` | Security alerts with explanations |

Every tool accepts `--help`. Exit codes are the same everywhere: `0`
success, `1` a clear error (for example a missing file), `2` invalid
command-line arguments. Lines that cannot be parsed are reported on stderr
with their line number and skipped. They never stop the whole run.

---

## 1. Packet preview: `netwatch.pcap_inspect`

Reads a capture with TShark and prints one line per packet.

```bash
python -m netwatch.pcap_inspect data/pcaps/capture.pcapng --limit 15
```

Output for a small synthetic capture (documentation addresses only):

```
   #  Time                         Source                  Destination             Protocol    SrcPort  DstPort  Length
-----------------------------------------------------------------------------------------------------------------------
   1  2025-03-10 08:00:00.000 UTC  192.0.2.10              192.0.2.53              DNS           53001       53      71
   2  2025-03-10 08:00:01.250 UTC  192.0.2.10              198.51.100.20           TCP           50000      443      54
   3  2025-03-10 08:00:02.500 UTC  198.51.100.20           192.0.2.10              TCP             443    50000      54
   4  2025-03-10 08:00:03.750 UTC  192.0.2.10              198.51.100.1            ICMP              -        -      46
   5  2025-03-10 08:00:04.000 UTC  -                       -                       ARP               -        -      42
   6  2025-03-10 08:00:05.250 UTC  192.0.2.10              192.0.2.53              DNS           53002       53      45
```

Packet 1 is a DNS query, 2 and 3 are the start of a TCP handshake (SYN,
SYN-ACK) to port 443, 4 is a ping, 5 is an ARP "who has 192.0.2.1?" request,
and 6 is a damaged DNS packet. Wireshark also shows it as DNS.

| Column | Meaning |
|--------|---------|
| `Time` | When the packet was recorded, in UTC |
| `Source` / `Destination` | IPv4 or IPv6 address that sent / received the packet |
| `Protocol` | Highest protocol layer TShark recognised. A trailing generic `data` layer (unidentified payload) is skipped, as in Wireshark |
| `SrcPort` / `DstPort` | TCP or UDP port (80 = HTTP, 443 = HTTPS, 53 = DNS, ...) |
| `Length` | Size of the whole packet as recorded, in bytes |

`-` means the field does not exist for that packet: ICMP has no ports, and
ARP has no IP addresses at all.

**Safety:** the tool only reads files. TShark runs with `-n` (no DNS
lookups while reading), from an argument list (no shell), and packet contents
are only displayed. On Windows the tool also finds TShark in
`C:\Program Files\Wireshark` when it is not on `PATH`.

---

## 2. Zeek connection log: `netwatch.zeek_conn`

Parses a Zeek `conn.log` (TSV or JSON) and previews the connections.

```bash
python -m netwatch.zeek_conn tests/fixtures/zeek/conn_tsv.log
```

```
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
```

| Column | Zeek field | Meaning |
|--------|-----------|---------|
| `Proto` | `proto` | Transport protocol: `tcp`, `udp` or `icmp` |
| `Source` | `id.orig_h` / `id.orig_p` | The **originator**, the side that started the connection |
| `Destination` | `id.resp_h` / `id.resp_p` | The **responder** |
| `Service` | `service` | Application protocol Zeek recognised (`http`, `dns`, `ssl`, ...) |
| `Duration` | `duration` | Seconds from first to last packet |
| `OrigBytes` / `RespBytes` | `orig_bytes` / `resp_bytes` | Payload bytes sent by each side |
| `OrigPkts` / `RespPkts` | `orig_pkts` / `resp_pkts` | Packets sent by each side |
| `State` | `conn_state` | How the connection went (see below) |

| State | Meaning | Why an analyst cares |
|-------|---------|----------------------|
| `SF` | Normal setup and close | Ordinary, completed traffic |
| `S0` | Attempt seen, no reply | Many of these can mean scanning or a dead host |
| `REJ` | Attempt rejected | The port is closed. Many in a row can mean scanning |
| `RSTO` / `RSTR` | Established, then reset by one side | Aborted connections |
| `OTH` | No TCP handshake seen | Midstream captures, ICMP, odd traffic |

**How missing values work:** `-` means Zeek did not record the value. An
`S0` connection got no reply, so it has no duration or byte counts. ICMP has
no ports: Zeek stores the ICMP type/code in the port columns, and the parser
moves them to separate fields so they are never mistaken for ports.

**Validation:** IP addresses must be valid, ports must be 0–65535, counts
cannot be negative, and text fields (`uid`, `proto`, `service`,
`conn_state`, `history`) may only contain the characters Zeek itself writes.
A line that breaks these rules is skipped and reported, for example
`line 12: field 'orig_bytes': not a whole number: 'lots'`.

---

## 3. Traffic summary: `netwatch.analyzer`

Loads the connections into a pandas DataFrame and summarises them.

```bash
python -m netwatch.analyzer data/demo/conn_demo.log --top 5
```

```
Format:          Zeek TSV
Connections:     450 (0 line(s) skipped, 0 duplicate(s) removed)
Time range:      2025-03-10 08:00:24 UTC -> 2025-03-10 08:58:49 UTC (58m 24s)
Source IPs:      10 unique
Destination IPs: 19 unique
Bytes sent:      536.7 KB by originators (428 of 450 connections recorded), 13.4 MB by responders (428 of 450 recorded)
Avg duration:    9.923 s (426 of 450 connections recorded)

Protocols
proto  connections  percent
  udp          230     51.1
  tcp          216     48.0
 icmp            4      0.9

Top 5 source IPs
      src_ip  connections
  192.0.2.30          120
203.0.113.66           60
...
Connections over time (1min buckets, UTC)
  2025-03-10 08:00:00       6  ##
...
```

- **Missing is not zero:** byte totals and averages use only the values
  Zeek recorded, and say how many connections that was ("428 of 450").
- **Deterministic:** ties in top-N tables are broken by IP address (numerically) or port.
- **No double counting:** a connection that appears twice (same Zeek `uid`) is counted once.
- **UTC everywhere**, and quiet periods appear as 0 in the timeline.

---

## 4. Detection: `netwatch.detection`

Runs the four detection rules and prints each alert with its explanation.

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
    Why:          203.0.113.66 contacted 60 different TCP ports on 192.0.2.20 within 60 s
                  (threshold: 15 ports within 60 s). 60 connections from 2025-03-10 08:20:00 UTC to
                  2025-03-10 08:20:23 UTC; connection states: REJ=50, S0=8, RSTO=2. This pattern can
                  indicate a port scan (reconnaissance), but authorised scanners and some
                  applications behave the same way.
    Events:       COULTAXAtpdeX54dAM, CYfJNCJHI7a1cGFHIB, CV6A7B3qfVfcq9avW9, CB85xNhdHXcNJSVWRQ, CnxMVHOR7UxgphbEDw ... (+55 more)
```

Options (defaults in brackets):

| Option | Rule | Meaning |
|--------|------|---------|
| `--scan-ports N` [15], `--scan-window S` [60] | NW-001 | distinct ports on one host within S seconds |
| `--rate-connections N` [100], `--rate-window S` [60] | NW-002 | connections from one source within S seconds |
| `--watchlist 23,3389,...` | NW-003 | destination ports to flag |
| `--failed-attempts N` [10], `--failed-window S` [60] | NW-004 | failed TCP attempts to one service within S seconds |
| `--rules NW-001,NW-004` [all] | all | which rules to run |

```bash
python -m netwatch.detection data/demo/conn_demo.log --scan-ports 50 --rules NW-001,NW-004
```

With 50 instead of 15 ports the scan alert keeps the same ID but becomes
Medium instead of High, because 60 ports is no longer at least 3 × the threshold.

Rule logic, severities and false positives: [DETECTION_RULES.md](DETECTION_RULES.md).

---

## 5. Rebuilding the demo data: `scripts/generate_demo_data.py`

```bash
python scripts/generate_demo_data.py
```

Rewrites `data/demo/conn_demo.log`, `data/demo/conn_demo.json` and
`tests/fixtures/zeek/normal_traffic.log`. The random seed is fixed, so the
files come out identical every time. See [data/demo/README.md](../data/demo/README.md).
