# Synthetic Zeek conn.log fixtures

These files are **hand-made test data**, not real traffic. All addresses come
from ranges reserved for documentation (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32), so they can never belong to a real host.

| File | Format |
|------|--------|
| `conn_tsv.log` | Zeek's default tab-separated format with `#` header lines |
| `conn_json.log` | Zeek's JSON format (`LogAscii::use_json=T`): one object per line |

Both files describe the **same six connections**, so the tests can check
that both formats produce identical records:

| # | Connection | Why it is included |
|---|------------|--------------------|
| 1 | TCP → port 80, `http`, state `SF` | A normal, complete connection |
| 2 | UDP → port 53, `dns`, state `SF` | UDP request/response |
| 3 | TCP → port 22, state `S0` | No reply: duration and byte counts are unset (`-`) |
| 4 | TCP → port 23, state `REJ` | Rejected (closed port) |
| 5 | ICMP echo, type 8 / code 0 | No ports: Zeek stores type/code in the port columns |
| 6 | IPv6 UDP → port 5353 | IPv6 addresses |
