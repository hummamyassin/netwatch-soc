# Learning Log

A running record of concepts learned while building NetWatch SOC.
Add to it at the end of each milestone, in your own words.

## The big picture: how data travels through NetWatch SOC

1. Computers talk in **packets**. A capture tool records them into a
   **PCAP** file, and **TShark** (Wireshark's command-line twin) can list them:
   `pcap_inspect.py` does exactly that.
2. Packets are too detailed for everyday monitoring, so **Zeek** groups them
   into **connections** and writes one line per connection to **conn.log**.
3. `zeek_conn.py` is the **parser**. It reads conn.log (TSV or JSON),
   checks every value, and turns each good line into a `ConnRecord`. Bad
   lines are reported, never silently used.
4. `analyzer.py` puts the records into a **pandas** table and answers
   "what does this traffic look like?": top talkers, ports, protocols,
   connection states, bytes and a timeline.
5. `detection.py` applies **detection rules**. When a pattern crosses a
   **threshold** inside a time window, it creates an **alert** with a
   **severity**, an explanation and the exact connections behind it.
6. `dashboard.py` shows everything in a browser, and `investigation.py`
   lets an analyst **triage** each alert: New → Investigating → Closed,
   with notes and a final verdict (the disposition).

Each module only talks to the next one, so every step can be tested on its
own (see `docs/ARCHITECTURE.md` for the technical version).

## Glossary

| Term | Plain-English meaning |
|------|-----------------------|
| **Packet** | One small unit of data sent over a network, wrapped in layers: Ethernet → IP (addresses) → TCP/UDP (ports) → application data |
| **PCAP / PCAPNG** | File formats that store recorded packets with timestamps. PCAPNG is the newer one Wireshark saves by default. Treat them as sensitive |
| **Connection** | A conversation between two endpoints (IP + port on each side), from the first packet to the last. Zeek logs one line per connection |
| **TCP** | Connection-oriented transport: a handshake first (SYN, SYN-ACK, ACK), then reliable, ordered delivery. Used by web, SSH, RDP... |
| **UDP** | Connectionless "fire and forget" transport: no handshake, no delivery guarantee. Used by DNS, NTP, mDNS... |
| **TShark** | The command-line version of Wireshark: reads captures and prints chosen packet fields |
| **Zeek** | An open-source network security monitor that turns traffic into structured logs (conn.log, dns.log, http.log, ...) |
| **conn.log** | Zeek's connection log: who talked to whom, ports, protocol, duration, bytes, packets, and how the connection ended (`conn_state`) |
| **TSV** | Tab-Separated Values: a text table where columns are separated by tabs. Zeek's default log format, with `#` header lines |
| **JSON** | JavaScript Object Notation: text made of `"key": value` pairs. Zeek can write one JSON object per line |
| **Parser** | Code that reads raw text and turns it into structured, checked data, rejecting anything that does not fit |
| **pandas** | A Python library for tables (DataFrames): counting, grouping, sorting and time-series work in a few lines |
| **Detection rule** | A precise, written condition that marks activity as worth reviewing, e.g. "≥ 15 distinct ports on one host within 60 s" |
| **Threshold** | The value a measurement must reach for a rule to fire. Too low: noise. Too high: missed activity |
| **Time window** | How close together events must be to count together, e.g. "within 60 seconds" |
| **Alert** | The output of a rule: what was seen, when, between which hosts, why it matters, and the evidence |
| **False positive** | An alert on harmless activity, e.g. the IT team's vulnerability scanner looking like an attacker's port scan |
| **True positive** | An alert on activity that really was malicious or unwanted |
| **Severity** | How urgently an alert should be looked at (High / Medium / Low), based on how strong the signal is, not proof of damage |
| **Alert triage** | Quickly deciding what an alert means and how much attention it needs: read it, check the evidence, decide |
| **Disposition** | The analyst's conclusion when closing an alert: True Positive, False Positive, Benign / Expected Activity, Inconclusive |
| **Incident investigation** | The deeper follow-up when an alert looks real: gather evidence, establish what happened and when, document it, recommend actions |
| **SOC** | Security Operations Centre: the team (and tools) that monitors alerts and responds to incidents |
| **Documentation IP ranges** | Address blocks reserved for examples (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32). They never belong to real hosts, so they are safe in test data |

---

## Milestone 1: Project foundation, PCAP and TShark

### Networking concepts
- **Packet**: one unit of data sent over a network. It is wrapped in layers:
  Ethernet (local link) → IP (addresses) → TCP/UDP (ports) → application (HTTP, DNS, …).
- **IP address**: identifies a host. IPv4 looks like `192.0.2.1`, IPv6 like `fe80::1`.
- **Port**: identifies a service on a host. Well-known ports: 53 DNS,
  80 HTTP, 443 HTTPS, 22 SSH. Only TCP and UDP have ports.
- **TCP vs UDP**: TCP is connection-based and reliable (a handshake first,
  e.g. web traffic). UDP is fire-and-forget (e.g. DNS queries).
- **ICMP** (ping, "host unreachable") and **ARP** ("who has this IP?" on a
  LAN) have no ports. ARP has no IP header at all. This is why a parser
  must not assume every packet is TCP/UDP.

### Capture files
- **PCAP / PCAPNG**: file formats that store recorded packets with timestamps.
  PCAPNG is the newer format Wireshark saves by default.
- Captures can contain sensitive data (credentials, cookies, internal IPs).
  Treat them like secrets and never commit them to Git.

### Tools
- **Wireshark**: GUI to explore packets. **TShark**: the same engine on the command line.
- `tshark -r file.pcap`: read a file (no live capture).
- `-T fields -e ip.src -e ip.dst …`: print only chosen fields, which is easy to parse.
- `-n`: disable name resolution, so reading a file doesn't send DNS queries.
- `frame.protocols`: the full protocol stack of a packet, e.g. `eth:ethertype:ip:udp:dns`.

### Secure coding
- **Command injection**: building a shell command from user input
  (`"tshark -r " + filename`) lets a file name like `x; del *` run extra
  commands. Passing a **list** to `subprocess.run` without `shell=True` sends
  each item as one argument, so this can't happen.
- **Untrusted input**: capture files may come from attackers. Only display
  their contents and never execute them. Keep Wireshark updated, because its
  parsers have had security bugs.
- Validate inputs early (file exists, is a file, isn't empty, limit is in range)
  and give clear error messages.

### Testing
- **Mocking** (`unittest.mock`): replace `subprocess.run` or `find_tshark`
  with a fake so tests run without TShark installed.
- `skipIf`: run a real-tool test only when the tool is available.

### Questions to explore
- Open a sample capture in Wireshark and find a TCP three-way handshake (SYN, SYN-ACK, ACK).
- What's the difference between `frame.len` and the IP total length?
- Why might the same IP appear as both source and destination in a conversation?

---

## Milestone 2: Zeek structured logs (conn.log)

### Packets vs connections
- Wireshark shows **packets**. Zeek groups packets into **connections**
  (also called flows) and writes one summary line per connection.
- A web page load might be 20 packets but only 1 line in `conn.log`. This is
  why analysts start with logs: they are smaller and easier to search.
- Zeek writes many logs from the same traffic: `conn.log` (every connection),
  `dns.log`, `http.log`, `ssl.log`, … They are linked by the connection **`uid`**.

### Key conn.log fields
- `id.orig_h` / `id.orig_p`: the **originator**, who started the connection.
- `id.resp_h` / `id.resp_p`: the **responder**.
- `proto`: transport (`tcp`/`udp`/`icmp`). `service`: application protocol Zeek
  recognised by looking at the traffic, not just the port number.
- `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`: how long
  and how much in each direction. A big `orig_bytes` with a small
  `resp_bytes` means the inside host *sent* a lot, which may matter later for
  data-exfiltration ideas.
- `conn_state`: how the connection went. `SF` = normal, `S0` = no reply,
  `REJ` = rejected. Lots of `S0`/`REJ` from one host is a classic sign of scanning.
- `history`: a letter per event. Uppercase = originator, lowercase = responder.
  `S` SYN, `h` SYN-ACK, `A` ACK, `D` data, `F` FIN, `R` RST.
  So `ShADadFf` is a normal TCP conversation.

### Log formats
- **TSV** (default): `#` header lines describe the file. `#fields` names the
  columns, and `-` means unset. Read columns **by name** from `#fields`,
  never by fixed position, because columns differ between Zeek versions and configs.
- **JSON** (`LogAscii::use_json=T`): one object per line ("NDJSON"). Unset
  fields are left out entirely.

### Data engineering ideas
- **Normalisation**: turn different input formats into one clean shape
  (`ConnRecord`), so every later step only has to handle one format.
- **Missing vs zero**: `None` (unknown) is different from `0` (measured as zero).
  An `S0` connection has *unknown* bytes, not zero bytes.
- **Validate at the edge**: check IPs (`ipaddress` module), port range
  (0–65535) and non-negative counts while parsing, so bad data never reaches
  detection rules.
- **Skip and report, don't crash**: one corrupt line shouldn't lose a whole
  log, but it must not be hidden either. Report it with its line number.
- **ICMP has no ports**: Zeek reuses the port columns for ICMP type/code.
  Treating "type 8" as "port 8" would confuse a port-scan rule later.
- **Synthetic fixtures** with documentation IP ranges (RFC 5737, RFC 3849)
  give realistic tests without any real or private traffic.

### Hardening added in Milestone 3
- Text fields (`uid`, `proto`, `service`, `conn_state`, `history`) only accept
  the characters Zeek writes. Logs are **untrusted input**. A crafted line could
  carry terminal escape codes (which recolour or rewrite your terminal) or
  Markdown links (which a dashboard might render). Rejecting them at the parser
  protects every tool that comes later.

### Questions to explore
- Which conn_state would you expect for a UDP DNS query that never got an answer?
- Why could `service` say `http` even when the port is not 80?
- What would many `REJ` connections from one source to many ports on one target suggest?

---

## Milestone 3: Network log analysis with pandas

### pandas basics used here
- A **DataFrame** is a table: each column has one data type, each row is one
  connection. `records_to_dataframe` builds it from the parser's `ConnRecord`s.
- **dtypes matter**: `ts` is `datetime64[us, UTC]` (real timestamps, so
  time maths works), ports and byte counts are `Int64` (whole numbers that
  can also be `<NA>`), and `duration` is `Float64`.
- `value_counts()` counts how often each value appears. `groupby([...]).size()`
  counts combinations (for example port + protocol). `resample("5min").size()`
  counts rows per time bucket.

### Analysis ideas
- **Top talkers**: the source IPs that start the most connections. A sudden
  new top talker is worth a look.
- **Top destination ports** show which *services* are used. Count them per
  protocol, because `53/udp` (DNS queries) and `53/tcp` (zone transfers, large
  answers) are different things.
- **Protocol mix**: mostly TCP plus some UDP (DNS, NTP) is typical. Lots of
  ICMP or unusual protocols can be interesting.
- **Connection states** summarise success vs failure. Many `S0`/`REJ` means
  many attempts that went unanswered or were refused.
- **Connections over time** shows bursts. Filling quiet buckets with 0 keeps
  the chart honest; leaving them out would hide gaps.

### Data quality habits
- **Missing is not zero.** `sum()` skips `<NA>`, so always report coverage:
  "668 bytes from 5 of 6 connections". Otherwise an analyst could wrongly
  conclude that a connection transferred nothing.
- **Deterministic sorting.** When two IPs have the same count, sort them by IP
  address (numerically: `10.0.0.2` before `10.0.0.10`). Reports that change
  order between runs confuse people and break tests.
- **Deduplicate by a stable ID.** Zeek's `uid` identifies a connection, so a
  repeated uid means the same connection was logged twice.
- **UTC everywhere.** Mixing time zones is a classic source of wrong
  timelines in investigations.

### Questions to explore
- In the analyzer output, which host is the "top talker", and is that expected?
- What would it mean if one host's `resp_bytes` were much larger than its `orig_bytes`?
- Why might a 1-second time bucket be a bad choice for a log covering a whole day?

---

## Milestone 4: Rule-based detection

### Key ideas
- A **detection rule** is a precise, written condition such as "one source
  contacts at least 15 distinct ports on the same host within 60 seconds".
  Writing it down exactly makes every alert explainable and testable.
- A **threshold** is the number that must be reached. A **time window** is
  how close together the events must be. Together they turn "a lot, quickly"
  into something a computer can check.
- **Deterministic** means same input + same settings = same output, every
  time. That is essential for trust: an analyst (or an auditor) can re-run the
  rule and get the same answer.

### Sliding windows
- For every connection, look back N seconds and count what is inside the
  window. If the count reaches the threshold, the rule fires.
- **Edges matter**: decide whether exactly 60 s apart is inside a 60-second
  window (here it is, so the window is inclusive) and test it.
- **Overlapping windows** would give dozens of alerts for one scan. Merging
  windows that share connections gives one alert per burst, which is easier
  for an analyst and avoids **alert fatigue**.

### False positives and severity
- A **false positive** is an alert on harmless activity: the IT team's
  vulnerability scanner looks exactly like an attacker's port scan. Every
  rule documents its usual false positives so the analyst knows what to check.
- **Severity** expresses how strong or unusual the signal is (High / Medium /
  Low), not proof of damage. Here it rises one level when the observed value
  is at least 3× the threshold.
- **Context vs evidence**: a connection to port 4444 is *context* (some
  exploit tools use it by default), not *evidence*. Any program can use any port.

### Zeek connection states in detection
- Failed TCP attempts are `S0` (no answer), `REJ` (refused), `RSTOS0`, `SH`.
- One-way UDP is also `S0`, but that is normal for mDNS or syslog, so UDP is
  never counted as "failed".
- A **missing** state is unknown, not failed. Never let missing data make an
  alert look stronger.

### Engineering habits
- **Stable alert IDs** (a hash of what the alert is about) let notes and
  ticket references survive re-runs.
- **Deduplication**: identical detections collapse into one alert, and a
  connection logged twice counts once.
- **Unsorted input**: Zeek writes conn.log in end-time order, so sort by
  start time before applying windows.
- **Test the boundaries**: threshold − 1 must not fire, threshold must fire,
  and the window edge must behave as documented.

### Questions to explore
- Why does a brute-force attack against an *open* SSH server not show up as
  failed connections in conn.log? Where would you look instead?
- Which demo alerts would you close as "Benign / Expected Activity", and why?
- How would you tune NW-002 for a network that has a busy proxy server?

---

## Milestone 5: The SOC dashboard

### What a SOC dashboard is for
- A **SOC (Security Operations Centre)** dashboard gives analysts a quick
  picture: how much traffic, which hosts are busiest, which services are
  used, and which alerts need attention, without reading raw logs.
- **KPIs** (key performance indicators) are the headline numbers at the
  top. Here: total connections, unique source/destination IPs, and alerts per
  severity.
- Charts answer "what changed?": a spike in the connections-over-time chart
  lines up with the port scan and the DNS burst in the demo data.

### Streamlit basics
- A Streamlit app is a Python script that **re-runs from top to bottom**
  every time the user clicks something. That is simple to write, but slow
  work must be **cached** (`st.cache_data`) so it only runs when its inputs
  change (a new file or new settings).
- `st.session_state` remembers values between those re-runs (for example
  the applied detection settings).
- A **form** (`st.form`) groups inputs so the expensive work runs once, when
  the user presses *Apply*, not after every keystroke.

### Keeping the UI honest and testable
- The UI file only *displays* results. Parsing, analysis, detection and
  formatting live in the `netwatch` package, where unit tests check them.
  If the UI showed made-up numbers, the tests would not notice. This way
  they do.
- Streamlit's `AppTest` runs the real dashboard script without a browser,
  clicks buttons, uploads files and reads the KPI values back.

### Security of a small web app
- **Untrusted uploads**: check extension and size, refuse binary files,
  parse in memory, never save or execute them. Use only the file *name* as a
  label, never as a path.
- **Markdown injection**: Streamlit renders Markdown, so text from a file
  could become a link or a remote image (which leaks that you opened it).
  Escape it (`safe_md`) or show it in a table or code block.
- **Exposure**: by default some servers listen on every network interface.
  `server.address = "localhost"` keeps the dashboard and investigation notes
  on this computer. Telemetry is turned off with `gatherUsageStats = false`.

### Questions to explore
- Which chart would show you a port scan fastest, and which a DNS burst?
- Why is caching keyed on the file *content* (a hash) rather than its name?
- What could go wrong if the dashboard listened on all network interfaces in a café?

---

## Milestone 6: Alert investigation workflow

### Triage in a SOC
- **Triage** means deciding quickly how much attention an alert needs. An
  analyst reads what fired and why, checks the supporting evidence (here,
  the exact connections from conn.log), and decides.
- A **status** shows where an alert is in the process: New (nobody has
  looked), Investigating (someone owns it), Closed (decided).
- A **disposition** records the conclusion:
  - *True Positive*: real malicious or unwanted activity.
  - *False Positive*: the rule fired on activity it should not match. This
    is a reason to tune the rule.
  - *Benign / Expected Activity*: the rule did its job, but the activity is
    allowed, e.g. the admin's RDP session. This is a reason to document an exception.
  - *Inconclusive*: not enough evidence. Say what you would need to decide.
- **Notes** are the audit trail: what you checked, what you found, and why
  you closed it. Good notes let a colleague (or you, next month) understand
  the decision.

### Investigating the demo alerts (examples)
- *Possible Port Scan* from 203.0.113.66: 60 ports in 24 s from an external
  host, mostly refused. Ask: is this an approved scanner? Did any port answer
  (22 and 80 did)? Likely True Positive (reconnaissance).
- *Repeated Failed Connections* to 198.51.100.70:8080: an internal client
  retrying every 5 s with no answer. Ask: is that server down? Likely
  Benign / Expected Activity, and worth telling the server owner.
- *Suspicious Destination Port* 3389: an internal RDP session. Ask: is
  192.0.2.14 an admin workstation? If yes, Benign / Expected Activity.

### Engineering ideas
- A **state machine** lists the allowed transitions explicitly. Checking
  "is this action allowed from the current status?" prevents impossible
  states, such as an alert that is Investigating but still has a disposition.
  A unit test caught exactly that bug during development.
- **Validate, then change**: check every input before modifying anything,
  so a failed action leaves the case untouched.
- **Session state is not storage.** It lives in memory for one browser
  session. Real SOC tools keep cases in a database or ticket system, which
  is a deliberate next step, not part of this milestone.
- **Isolation**: investigation records are keyed by a hash of the dataset,
  so notes for one log can never show up on another log.

### Questions to explore
- Which demo alert would you close as False Positive, and how would you
  change the rule settings so it does not fire again?
- What information would you need before closing the 4444 alert?
- Why is it useful that the same data and settings always give the same alert ID?

---

## Final QA and portfolio preparation

### What the final review found and fixed
- **Duplicated helpers**: three slightly different timestamp formatters and
  three copies of the "skipped lines" CLI warning became one of each. One
  copy was even missing the "... and N more" summary. Duplicates drift apart;
  shared helpers don't.
- **An "illustrative" example that was never run**: the README showed packet
  output typed from memory. It was replaced with real output from the tool
  on a synthetic capture, and that capture became a test. Documentation
  should show what the software actually does.
- **Version claims need checking**: the README said Python 3.10+ would work,
  but pandas 3 and Streamlit need 3.11+. The package metadata
  (`Requires-Python`) settles it.

### Security review checklist (and how this project answers it)
- Secrets or credentials in Git? None. `.env`, keys and Streamlit secrets are ignored.
- Personal data or real traffic? None tracked. Fixtures and demo data use
  documentation IP ranges, and real captures/logs are ignored by `.gitignore`.
- Unsafe file handling? Uploads are size- and type-checked, parsed in
  memory, never written to disk or executed.
- Unsafe subprocess use? Only TShark, from an argument list (no shell), with a timeout.
- Path traversal? Uploaded file names are reduced to a display label and
  never used as paths. Demo files come from a fixed list.
- Dangerous deserialisation? Only `json.loads` on data. No pickle/YAML loading of user input.
- Unnecessary network access? None at runtime: the dashboard binds to
  localhost and Streamlit telemetry is off.
- Exposure of investigation data? Notes stay in the browser session on this
  computer. Note the trade-off: they are also lost on reload.

### Questions to explore
- Which of the limitations in the README would you fix first for a real SOC, and why?
- How would you store investigation notes durably without adding a big database server?
