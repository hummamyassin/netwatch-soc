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

### Questions to explore
- Which conn_state would you expect for a UDP DNS query that never got an answer?
- Why could `service` say `http` even when the port is not 80?
- What would many `REJ` connections from one source to many ports on one target suggest?
