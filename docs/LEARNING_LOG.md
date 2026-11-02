# Learning Log

A running record of concepts learned while building NetWatch SOC.
Add to it at the end of each milestone, in your own words.

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
