# Detection validation lab: real port-scan captures

The previous lab ([REAL_PCAP_LAB.md](REAL_PCAP_LAB.md)) showed that benign
traffic produces **no** alerts. This lab asks the opposite question: when a
capture *independently documented* as suspicious is analysed, do the existing
rules find it, and is every alert backed by real evidence?

Run on 2026-11-02 against commit `7674a06`. Thresholds were **not** changed,
no rule was added, nothing was scanned or generated, and no captured content
was executed. Captures and Zeek logs stay out of Git.

**Labels used below:** **Verified** = measured in this lab. **Ground truth** =
stated by the dataset's own README. **Interpretation** = the analyst's
reading. **Unknown** = not established.

## 1. Objective

Validate NW-001 to NW-004 against real nmap scan traffic with documented ground
truth, and explain every detection, every silence and the edge cases.

## 2. Dataset and provenance

| Item | Value |
|------|-------|
| Name | `NMap-Captures.zip`, "Some captures of various NMap port scan techniques" |
| Listed on | <https://wiki.wireshark.org/SampleCaptures> (official Wireshark sample collection) |
| URL | `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip` (redirects to the Wireshark GitLab wiki) |
| Archive SHA-256 | `3fac3f99402b5b6a2bc819ce7c9ba4aab58756e3353412a7834bfce02f098305` (114,641 bytes) |
| Stored at | `data/pcaps/nmap/` (git-ignored); extracted with a script that refuses paths and directories |
| License | **Not stated** on the sample page. Used locally for training only; not redistributed |

| Capture | SHA-256 (first 16 hex) | Packets | Duration |
|---------|------------------------|---------|----------|
| nmap_standard_scan | `f59479ce3b783ad0` | 2,004 | 34.1 s |
| nmap_OS_scan | `12b463952878bf01` | 2,056 | 36.6 s |
| nmap_OS_scan_succesful | `2eaca3a56fbdc1c9` | 2,052 | 18.9 s |
| nmap_ACK_scan_on_port_80 | `3749f9ca8fec27a8` | 6 | 13.1 s |
| nmap_ACK_scan_on_port_80_2 | `dcade767862f4a70` | 20 | 13.1 s |
| nmap_zombie_scan | `c47d75edcafdd570` | 42 | 13.9 s |

All six are classic pcap, recorded on 2014-02-07 between 09:32 and 10:14 UTC.

## 3. Ground truth (from the dataset's README)

Captured "from the target with interface in promiscuous mode". Lab addresses:
scanner `192.168.100.103`, target `192.168.100.102`, zombie / second target `192.168.100.101`.

| Capture | Documented command and behaviour |
|---------|----------------------------------|
| standard_scan | `nmap 192.168.100.102`: default nmap scan |
| OS_scan | `nmap -O -Pn 192.168.100.102`: OS detection that failed; "target had only filtered ports" |
| OS_scan_succesful | `nmap -O -Pn 192.168.100.101`: OS detection against a host with one open and one closed port |
| ACK_scan_on_port_80 | `nmap -p80 -sA -Pn 192.168.100.102`: ACK scan of one port |
| ACK_scan_on_port_80_2 | `nmap -p80 -sA -Pn -f -S 192.168.100.101 ...`: fragmented ACK scan with a spoofed source |
| zombie_scan | `nmap -p80 -Pn -sI 192.168.100.101:2869 192.168.100.102`: idle scan of .102 through zombie .101 port 2869; the scanner-zombie traffic is "pretty noisy" |

The README labels whole captures, not individual packets. There are no
per-connection labels, so **precision and recall are not calculated**.

## 4. TShark observations (verified)

- standard_scan: 2,000 TCP frames + 4 ARP.
- OS scans: about 2,000 TCP frames plus a few ICMP and UDP probes (OS fingerprinting).
- ACK scans: 2 TCP frames each (the second also has 1 UDP broadcast).
- zombie_scan: 36 TCP frames.

## 5. Zeek execution (verified)

Zeek 8.0.11 in WSL2 (Ubuntu 26.04.1), offline, one fresh directory per capture:

```bash
cd "$(mktemp -d)" && /opt/zeek/bin/zeek -C -r "/mnt/c/.../data/pcaps/nmap/extracted/nmap_standard_scan"
```

| Capture | Exit | conn.log rows | Other logs | Zeek warning |
|---------|------|---------------|------------|--------------|
| standard_scan | 0 | 2,000 | reporter | "trace ... contains only TCP control packets, which may indicate it's been pre-filtered" |
| OS_scan | 0 | 2,011 | dhcp | none |
| OS_scan_succesful | 0 | 2,013 | weird | none |
| ACK_scan_on_port_80 | 0 | 2 | reporter | same "only TCP control packets" warning |
| ACK_scan_on_port_80_2 | 0 | 3 | weird | none |
| zombie_scan | 0 | 15 | reporter, weird | same "only TCP control packets" warning |

The warning is expected: scans send SYN/ACK/RST packets with no payload, so the
trace looks "control only". It does not mean data was lost.

## 6. Connection statistics (verified, NetWatch analyzer)

| Capture | Connections | Src / dst IPs | Protocols | States | Byte counts recorded |
|---------|-------------|---------------|-----------|--------|----------------------|
| standard_scan | 2,000 | 1 / 1 | tcp 2,000 | S0 2,000 | 0 of 2,000 |
| OS_scan | 2,011 | 2 / 3 | tcp 2,006, udp 4, icmp 1 | S0 2,006, OTH 3, SH 2 | 9 of 2,011 |
| OS_scan_succesful | 2,013 | 1 / 1 | tcp 2,011, icmp 1, udp 1 | S0 1,993, RSTO 10, REJ 5, RSTRH 3, OTH 1, RSTR 1 | 21 of 2,013 |
| ACK_scan_on_port_80 | 2 | 1 / 1 | tcp 2 | OTH 2 | 0 of 2 |
| ACK_scan_on_port_80_2 | 3 | 1 / 2 | tcp 2, udp 1 | OTH 2, S0 1 | 0 of 3 |
| zombie_scan | 15 | 3 / 2 | tcp 15 | REJ 14, S0 1 | 15 of 15 |

- In standard_scan, **each of 1,000 ports was probed exactly twice** from 2
  source ports. That is nmap's default 1,000-port scan sending one retry for
  unanswered probes. Each unanswered SYN is its own Zeek `S0` connection.
- **Incomplete records are handled correctly.** S0 connections carry no byte
  or duration values, and the analyzer reports "0 of 2,000 recorded" instead
  of a false total of 0 bytes.

## 7. Rule thresholds (defaults, unchanged)

| Rule | Condition | Base severity |
|------|-----------|---------------|
| NW-001 Possible Port Scan | ≥ 15 distinct ports, one source → one host, within 60 s | Medium (High at ≥ 45) |
| NW-002 High Connection Rate | ≥ 100 connections from one source within 60 s | Low (Medium at ≥ 300) |
| NW-003 Suspicious Destination Port | traffic that reached 23, 3389, 4444, 5900, 6667 or 31337 (failed TCP attempts excluded) | Low |
| NW-004 Repeated Failed Connections | ≥ 10 failed TCP attempts (S0/REJ/RSTOS0/SH), one source → one host:port, within 60 s | Medium (High at ≥ 30) |

## 8. Results per rule (verified)

| Capture | NW-001 | NW-002 | NW-003 | NW-004 | Total |
|---------|--------|--------|--------|--------|-------|
| standard_scan | **1 High** (1,000 ports) | **1 Medium** (2,000 conns) | 0 | 0 | 2 |
| OS_scan | **1 High** (1,002 ports) | **1 Medium** (2,010 conns) | 0 | 0 | 2 |
| OS_scan_succesful | **1 High** (1,000 ports on .101) | **1 Medium** (2,013 conns) | 0 | 0 | 2 |
| ACK_scan_on_port_80 | 0 | 0 | 0 | 0 | 0 |
| ACK_scan_on_port_80_2 | 0 | 0 | 0 | 0 | 0 |
| zombie_scan | 0 | 0 | 0 | **1 Medium** (13 REJ to .101:2869) | 1 |

Alert IDs (stable for these conn.log files): standard_scan `NW-001-b287ab9a00fb`,
`NW-002-160b84ac8e83`; OS_scan `NW-001-8f2c715246cc`, `NW-002-d9cb420ccf27`;
OS_scan_succesful `NW-001-897b08bd8a3f`, `NW-002-6b15f7882ee2`; zombie_scan
`NW-004-d409b4f500c1`.

## 9. Evidence behind each detection (verified)

For every alert, every supporting event ID exists in its conn.log and the
number of IDs equals the alert's connection count. Running detection on
shuffled rows gives identical alerts and IDs.

- **NW-001 standard_scan:** 192.168.100.103 → 192.168.100.102, 1,000 distinct
  TCP ports, 2,000 S0 connections, 09:32:35–09:32:56 UTC. Severity High because
  1,000 ≥ 3 × 15.
- **NW-002 standard_scan:** the same 2,000 connections, one destination. Medium because 2,000 ≥ 3 × 100.
- **NW-001 OS_scan:** 1,002 ports on .102 (states S0 2,002, OTH 2, SH 2).
- **NW-002 OS_scan:** 2,010 connections to **2 destinations**. 2,009 went to
  .102, and one was a DHCP exchange with 192.168.100.100:67.
- **NW-001/002 OS_scan_succesful:** 1,000 ports / 2,013 connections, all to
  .101, the target named in the README. States include RSTO 10, REJ 5 and RSTR 1:
  the host answered on some ports, unlike the fully filtered .102.
- **NW-004 zombie_scan:** 13 connections .103 → .101:2869, all `REJ` with Zeek
  history `Hr` (an unsolicited SYN-ACK from the scanner, answered with a reset).
  These are the idle-scan probes the README calls "noisy".

## 10. False positives, false negatives, coverage

**Confirmed matching detections (ground truth agrees):**
- All three captures documented as nmap port scans (standard and both OS
  scans) raised NW-001 with the documented scanner and target, and the
  measured port count (1,000) equals nmap's default port count.
- The zombie capture raised NW-004 on the scanner-to-zombie traffic the README
  describes. *Interpretation:* the alert is on real, documented suspicious
  activity, but its wording ("failed connection attempts") does not describe
  idle-scan probes precisely. The packets are unsolicited SYN-ACKs, which Zeek
  classifies as `REJ`.

**Potential false positives:**
- None of the alerts fired on traffic outside the documented scans. One
  qualification: NW-002 on OS_scan includes one DHCP connection in its
  evidence, because the rule counts all of a source's connections. The alert
  is right; one supporting event is ordinary background traffic.
- In a real network the same patterns can come from authorised scanners, so
  "matches ground truth" here does not mean the rules are free of false
  positives in general.

**Documented behaviour not alerted, and why:**

| Behaviour | Why no alert | Classification |
|-----------|--------------|----------------|
| ACK scan of port 80 (both captures) | 2 probes to one port. No rule targets single-port ACK probes. Zeek records them as `OTH` (no handshake), not a failed state | **Outside rule coverage**, not a false negative |
| Spoofed source in ACK_scan_2 | The scan appears to come from .101; NetWatch cannot tell a spoofed source from a real one | **Outside coverage** (needs packet-level analysis) |
| The idle scan of .102 itself | One spoofed SYN from .101 to .102:80 (`S0`). One port, one attempt | **Outside coverage**. The noisy scanner-zombie side was detected instead |
| Watchlisted ports in the scans (23, 3389, 5900...) | Probed 12–13 times per scan, but **never answered** (all S0). NW-003 deliberately ignores failed TCP attempts | **Did not meet the rule's criteria** (by design) |
| NW-004 on the port scans | Each port was probed at most twice; NW-004 needs ≥ 10 failures to the *same* port | **Did not meet the rule's criteria** (by design; NW-001 covers breadth) |

No implementation bug was found, so no code was changed. A missing alert is
not proof that traffic is safe.

## 11. Dashboard investigation (verified headlessly)

The real `dashboard.py` was driven with Streamlit AppTest, uploading the real
standard_scan `conn.log`:

- KPIs: 2,000 connections, 1 source IP, 1 destination IP, 2 alerts (High 1, Medium 1). 5 charts rendered. No errors or warnings.
- Alert table: NW-001 High and NW-002 Medium, both 192.168.100.103 → .102. The Medium filter left only "High Connection Rate".
- Investigation of `NW-001-b287ab9a00fb`: 2,000 supporting-evidence rows covering 1,000 ports, all S0.
- Workflow: New → Investigating, note added ("Ground truth (README in
  NMap-Captures.zip): nmap default scan by .103 against .102. Evidence: 1000
  distinct TCP ports, each probed twice, all S0 (no replies), 21 s."), closed
  as **True Positive**. That disposition is justified only because the
  dataset's README independently documents the scan. The queue then showed
  it Closed and NW-002 still New.
- Investigation state is session-only and was not persisted.

*Not verified by me:* uploading in a visible browser (the in-app browser
cannot attach local files). See "Your turn" below.

## 12. Tests

`python -m unittest`: **252 run, 252 passed, 0 failed, 0 skipped** (TShark
installed). Already covered by the existing tests: deterministic and
order-independent detection, alert-to-evidence association, missing
values, the zero-alert path, and dashboard regressions. No new test was needed
because no defect was found.

## 13. Known limitations

- **Labels are per capture, not per connection**, so detection accuracy cannot be measured statistically.
- **No license** is stated for the captures, so they are not redistributed.
- **Lab network only.** Results come from a 2014 lab network and one scanner.
  Real networks add background noise and other scanners.
- **Rule wording.** NW-004 describes idle-scan probes as "failed connection
  attempts", which is accurate for Zeek's `REJ` state but not for what the packets are.
- **No packet-level analysis.** Spoofed sources, fragmentation and ACK scans
  are not distinguishable from conn.log alone.
- **Unstable uids across Zeek runs.** Re-running Zeek creates new uids, so alert IDs change between conversions.

## 14. Comparison with the benign http.cap lab

| | http.cap (benign) | NMap captures (documented scans) |
|---|---|---|
| Packets → connections | 43 → 3 | 2,004 → 2,000 (standard scan) |
| Typical state | SF (completed) | S0 (no reply) |
| Distinct ports per source → host | 1 | 1,000 |
| Peak connections per second | 1 | 100–730 |
| Alerts | 0 | 2 per port scan, 1 for the zombie scan |
| Conclusion | No rule should fire, and none did | Breadth and rate rules fire on documented scans; single-port techniques fall outside the rules |

## 15. Reproduce it

1. Download `NMap-Captures.zip` from the URL above into `data/pcaps/nmap/`,
   check the SHA-256, list the archive, and extract only its flat files.
2. For each capture, run Zeek offline in an empty directory (command in section 5) and copy `conn.log` to `data/zeek_logs/nmap/<capture>/`.
3. `python -m netwatch.detection data/zeek_logs/nmap/nmap_standard_scan/conn.log`
4. `streamlit run dashboard.py`, choose **Upload a log**, select that `conn.log`, and investigate the NW-001 alert.

### Your turn

Upload `C:\Users\User\Desktop\NetWatch SOC\data\zeek_logs\nmap\nmap_standard_scan\conn.log`
at <http://localhost:8501> to see 2,000 connections and the two alerts in a real browser.

## 16. Glossary

| Term | Meaning |
|------|---------|
| Port scan | Probing many ports on a host to find which services exist (reconnaissance) |
| nmap | A widely used network scanner. The default scan probes the 1,000 most common TCP ports |
| ACK scan | Sends TCP ACK packets to learn whether a firewall filters a port, not whether it is open |
| Idle (zombie) scan | Scans a target while making it look as if a third "zombie" host is scanning, by watching the zombie's IP ID counter |
| Ground truth | Independent knowledge of what really happened (here, the dataset README) |
| True / false positive | An alert on real suspicious activity / an alert on harmless activity |
| False negative | Suspicious activity that a rule *should* have caught but missed. Behaviour a rule was never designed to see is "outside coverage" |
| S0 / REJ / OTH | Zeek states: no reply / rejected with a reset / no handshake seen |
| Zeek history `Hr` | The originator sent a SYN-ACK without a SYN (`H`), and the responder sent a reset (`r`) |
| Precision / recall | Share of alerts that are correct / share of real events that were alerted. These need per-event labels, which this dataset lacks |
