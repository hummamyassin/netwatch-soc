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
