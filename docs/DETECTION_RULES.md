# Detection rules

NetWatch SOC's detection engine (`netwatch/detection.py`) is **rule-based and
deterministic**. Every rule is a short Python function over Zeek `conn.log`
connections. The same log with the same configuration always produces the
same alerts with the same alert IDs. No AI or machine learning is involved in
deciding what becomes an alert.

> **Alerts are leads, not verdicts.** Each alert describes *possible*
> suspicious behaviour that an analyst should review. Every rule below
> lists ordinary reasons why it can fire on harmless traffic (false positives).

## Summary

| ID | Alert type | Looks for | Default threshold | Base severity |
|----|------------|-----------|-------------------|---------------|
| NW-001 | Possible Port Scan | One source contacting many **distinct ports** on the **same host** | ≥ 15 ports within 60 s | Medium |
| NW-002 | High Connection Rate | One source starting **many connections** | ≥ 100 connections within 60 s | Low |
| NW-003 | Suspicious Destination Port | Traffic that reached a **watchlisted port** | any connection (23, 3389, 4444, 5900, 6667, 31337) | Low |
| NW-004 | Repeated Failed Connections | Many **rejected or unanswered TCP attempts** to the same service | ≥ 10 failed attempts within 60 s | Medium |

The defaults are **demonstration values**. They suit the bundled demo data
and a small lab. A real network needs tuning: what counts as "many" depends
on the environment.

## How time windows work

NW-001, NW-002 and NW-004 use a **sliding window**:

1. Connections are sorted by start time (ties by event ID), so the order of
   lines in the log never matters. Zeek writes `conn.log` in *end-time*
   order, so logs are usually not sorted by start time.
2. For every connection, the window contains that connection and all earlier
   ones that started **at most N seconds before it** (the edge is inclusive:
   exactly 60 s apart is still inside a 60-second window).
3. If the window reaches the threshold, the rule triggers.
4. **Overlapping windows are merged.** If the next triggering window shares
   connections with the previous one, they belong to the same burst and the
   alert grows instead of a new alert being created. A long scan therefore
   produces **one** alert, not one per window.
5. A quiet gap longer than the window ends the burst. Activity after the gap
   that triggers again becomes a **new** alert.

Each alert records:

- `observed_value`: the **peak** measured in a single window (e.g. 61 distinct ports)
- `connection_count`: all supporting connections in the merged burst (e.g. 100)
- `threshold` and `window_seconds`: the configuration that was applied

## Severity

| Rule | Base | Raised one level when |
|------|------|-----------------------|
| NW-001 | Medium | observed ≥ 3 × threshold (e.g. ≥ 45 ports) → High |
| NW-002 | Low | observed ≥ 3 × threshold (e.g. ≥ 300 connections) → Medium |
| NW-003 | Low | never: a port match is contextual only |
| NW-004 | Medium | observed ≥ 3 × threshold (e.g. ≥ 30 failures) → High |

The factor (3) is `escalation_factor` in `DetectionConfig`. Severity reflects
**how strong and unusual the signal is**, not a confirmed impact.

## What counts as a "failed" connection

Zeek's `conn_state` says how a connection went. NW-004 counts a connection as
a failed attempt **only if it is TCP and its state is one of**:

| State | Meaning |
|-------|---------|
| `S0` | Attempt seen, no reply at all (often a firewall dropping it, or the host is down) |
| `REJ` | Attempt rejected: the target answered with a reset (port closed) |
| `RSTOS0` | Originator sent SYN, then RST, and never got a SYN-ACK |
| `SH` | Originator sent SYN, then FIN, and never got a SYN-ACK |

Never counted as failures:

- **Normal states** such as `SF`, `S1`, `RSTO`, `RSTR`, `OTH`.
- **Missing states.** If Zeek did not record a state, the engine does not guess.
- **UDP.** One-way UDP (state `S0`) is normal for mDNS, syslog, NTP broadcasts and more.

## NW-001 Possible Port Scan

**Logic.** Group TCP and UDP connections by *(source IP, destination IP,
protocol)*. Trigger when one window contains at least `port_scan_min_ports`
**distinct** destination ports.

- Repeating the same port many times is **not** a scan (that is NW-002 or NW-004).
- Ports spread over **different** targets are not combined. This rule looks
  for one host being probed.
- TCP and UDP are counted separately. ICMP has no ports and is ignored.
- All connection states count: a scan is visible whether the ports were open,
  closed or filtered. The explanation lists the states seen (e.g. `REJ=50, S0=8, RSTO=2`).

**False positives:** vulnerability scanners and asset inventory run by IT;
monitoring systems checking many services; applications that use many ports
(passive FTP, Windows RPC dynamic ports).

**Tuning:** raise `port_scan_min_ports` for servers with many services; add
known scanner IPs to an allow-list (future work).

## NW-002 High Connection Rate

**Logic.** Group all connections by *source IP*. Trigger when one window
contains at least `high_rate_min_connections` connections, whatever the
destination, port or protocol.

- If all connections go to one host, the alert shows that host. Otherwise
  `dst_ip` is empty (not invented) and the explanation names the busiest destination.

**False positives:** busy servers, proxies and NAT gateways that act for
many users; backups and update jobs; chatty or misconfigured applications
(the demo's DNS burst is a good example).

**Tuning:** set the threshold well above the busiest normal host's rate.

## NW-003 Suspicious Destination Port

**Logic.** Find connections whose destination port is on the watchlist.
Create one alert per *(source, destination, port, protocol)* covering all
matching connections in the log (no time window).

Rejected or unanswered TCP attempts (the failed states above) are
**excluded**. They are already covered by NW-001/NW-004, and a refused probe
did not reach a service. This keeps a single port scan from producing many
extra alerts.

Default watchlist:

| Port | Why it is on the list |
|------|------------------------|
| 23 | Telnet, unencrypted remote login |
| 3389 | RDP remote desktop, a common brute-force target |
| 4444 | Default listener port of some exploit frameworks |
| 5900 | VNC remote desktop |
| 6667 | IRC, historically used for botnet command and control |
| 31337 | Historically used by backdoors |

> **A watchlisted port is a contextual observation, not proof of
> malicious activity.** Port numbers are only conventions: any program can
> use any port, and remote-desktop ports are used legitimately every day.

**False positives:** administrators using RDP or VNC; software that happens
to use a listed port; approved security testing.

## NW-004 Repeated Failed Connections

**Logic.** Take TCP connections in a failed state and group them by
*(source, destination, destination port)*. Trigger when one window contains
at least `failed_min_attempts` failures.

- Successful connections in between do not reset the count, and they are
  not listed as supporting events.
- Failures to different ports are not combined (that pattern is NW-001).

**False positives:** a client retrying a server that is down or moved; a
misconfigured application; a firewall change that silently drops traffic
(the demo's 8080 retries are an example).

**Note:** brute-force attempts against an *open* service usually complete
the TCP handshake (state `SF`/`RSTO`), so they are not "failed connections"
at the network level. Detecting failed *logins* needs application logs (for
example SSH or RDP logs), which is outside this project.

## Alert fields

| Field | Meaning |
|-------|---------|
| `alert_id` | Stable ID, e.g. `NW-001-e76a1be8a006`: rule + SHA-256 fingerprint of source, destination, first/last time and supporting event IDs |
| `rule_id`, `alert_type` | Which rule fired |
| `severity` | `High`, `Medium` or `Low` |
| `src_ip`, `dst_ip` | `dst_ip` is empty when several destinations are involved (never invented) |
| `dst_ports`, `protocols` | Distinct values seen in the supporting connections (empty if Zeek recorded none) |
| `first_seen`, `last_seen` | UTC start times of the first and last supporting connection |
| `connection_count`, `destination_count` | Supporting connections and distinct destinations |
| `observed_value`, `threshold`, `window_seconds` | What was measured, against which setting |
| `explanation` | Plain-English reason, built only from the data and the configuration |
| `event_ids` | Supporting connections (Zeek `uid`, or `row-N` when the log has no uid), in time order |

**Stable IDs.** The ID depends only on the rule and the supporting
connections. Re-running the same log with the same settings gives the same
IDs, so investigation notes stay attached to the right alert. Changing a
threshold can change which connections support an alert, and then its ID
changes too. **Duplicates:** identical detections collapse into one alert,
and a connection logged twice (same uid) is only counted once.

## Trying it

```bash
python -m netwatch.detection data/demo/conn_demo.log
```

```bash
python -m netwatch.detection data/demo/conn_demo.log --scan-ports 50 --rules NW-001,NW-004
```

```bash
python -m netwatch.detection tests/fixtures/zeek/normal_traffic.log
```

The last command uses normal traffic only and should report **no alerts**.
