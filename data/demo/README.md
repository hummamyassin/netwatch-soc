# Demo dataset (synthetic)

`conn_demo.log` (Zeek TSV) and `conn_demo.json` (Zeek JSON) contain the same
**450 invented connections** covering one hour (2025-03-10 08:00–09:00 UTC).
They let you explore the analyzer, the detection rules and the dashboard
without any real capture.

- **Nothing here is real traffic.** All addresses come from ranges reserved
  for documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.
- The files are made by `scripts/generate_demo_data.py` with a fixed random
  seed, so regenerating them gives identical output.
- Rows are in Zeek's real order (by connection *end* time), so they are
  not sorted by start time.

## What is inside

| Time (UTC) | Activity | Expected alert (default settings) |
|------------|----------|-----------------------------------|
| all hour | 6 workstations doing DNS lookups and web browsing, NTP, mDNS, pings, an SSH admin session | none |
| 08:10 | 192.0.2.14 uses RDP (3389) to 198.51.100.25 | NW-003 Low, likely legitimate admin work |
| 08:20 | 203.0.113.66 probes 60 ports on 192.0.2.20 in 24 s | NW-001 High, possible port scan |
| 08:35 | 192.0.2.30 sends 120 DNS queries in 54 s | NW-002 Low, high connection rate |
| 08:42–08:52 | 192.0.2.12 connects to 203.0.113.80 on port 4444 three times | NW-003 Low, watchlisted port |
| 08:50 | 203.0.113.99 is refused 36 times on SSH (22) at 192.0.2.26 | NW-004 High, repeated failed connections |
| 08:55 | 192.0.2.11 retries 198.51.100.70:8080 every 5 s with no answer | NW-004 Medium, likely an unreachable server |

The mix is deliberate: some alerts look worrying and some are probably
harmless, so you can practise triage and record different dispositions.
