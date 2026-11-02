"""Generate NetWatch SOC's synthetic demo data (Zeek conn.log in TSV and JSON).

Run from the project root:
    python scripts/generate_demo_data.py

Writes:
    data/demo/conn_demo.log                 normal traffic + suspicious scenarios (Zeek TSV)
    data/demo/conn_demo.json                the same connections (Zeek JSON, one object per line)
    tests/fixtures/zeek/normal_traffic.log  normal traffic only (TSV), expected to raise no alerts

Everything is invented and reproducible (fixed random seed). Addresses come
only from ranges reserved for documentation, so no real host is involved:
    192.0.2.0/24     plays the "internal" network      (RFC 5737 TEST-NET-1)
    198.51.100.0/24  plays external services           (RFC 5737 TEST-NET-2)
    203.0.113.0/24   plays external suspicious hosts   (RFC 5737 TEST-NET-3)
    2001:db8::/32    IPv6 documentation prefix          (RFC 3849)

Scenarios included (with the default detection settings):
    08:10  192.0.2.14 uses RDP (3389) to a server         -> NW-003, likely benign admin work
    08:20  203.0.113.66 probes 60 ports on 192.0.2.20      -> NW-001 possible port scan
    08:35  192.0.2.30 sends 120 DNS queries in < 1 minute  -> NW-002 high connection rate
    08:42  192.0.2.12 talks to 203.0.113.80 on port 4444   -> NW-003 watchlisted port
    08:50  203.0.113.99 is refused 36 times on SSH (22)    -> NW-004 repeated failed connections
    08:55  192.0.2.11 retries an unreachable app server    -> NW-004, likely benign retries
"""

from __future__ import annotations

import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "data" / "demo"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "zeek"

SEED = 20250310
START = datetime(2025, 3, 10, 8, 0, 0, tzinfo=timezone.utc)

FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
          "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
          "tunnel_parents"]
TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count",
         "count", "string", "bool", "bool", "count", "string", "count", "count", "count", "count",
         "set[string]"]

WORKSTATIONS = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.15"]
RESOLVER = "192.0.2.53"
WEB_SERVERS = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.20",
               "198.51.100.21", "198.51.100.30", "198.51.100.31", "198.51.100.40"]

rng = random.Random(SEED)
used_uids: set[str] = set()


def new_uid() -> str:
    """A Zeek-style connection uid: 'C' followed by 17 letters/digits."""
    alphabet = string.ascii_letters + string.digits
    while True:
        uid = "C" + "".join(rng.choice(alphabet) for _ in range(17))
        if uid not in used_uids:
            used_uids.add(uid)
            return uid


def is_internal(ip: str) -> bool:
    return ip.startswith("192.0.2.") or ip.startswith("2001:db8:")


def ephemeral_port() -> int:
    return rng.randint(49152, 65535)


def connection(at: datetime, src: str, dst: str, dport: int, proto: str, state: str, *,
               sport: int | None = None, service: str | None = None, duration: float | None = None,
               orig_bytes: int | None = None, resp_bytes: int | None = None, history: str | None = None,
               orig_pkts: int = 1, resp_pkts: int = 0) -> dict:
    """One conn.log entry as a dict of Zeek field name -> value (None = unset)."""
    header = {"tcp": 40, "udp": 28, "icmp": 28}[proto] + (20 if ":" in src else 0)
    return {
        "ts": at, "uid": new_uid(), "id.orig_h": src, "id.orig_p": ephemeral_port() if sport is None else sport,
        "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "service": service, "duration": duration,
        "orig_bytes": orig_bytes, "resp_bytes": resp_bytes, "conn_state": state,
        "local_orig": is_internal(src), "local_resp": is_internal(dst), "missed_bytes": 0,
        "history": history, "orig_pkts": orig_pkts, "orig_ip_bytes": (orig_bytes or 0) + header * orig_pkts,
        "resp_pkts": resp_pkts, "resp_ip_bytes": (resp_bytes or 0) + header * resp_pkts, "tunnel_parents": None,
    }


def seconds(n: float) -> timedelta:
    return timedelta(microseconds=round(n * 1_000_000))


# ---------------------------------------------------------------------------
# Traffic
# ---------------------------------------------------------------------------

def normal_traffic() -> list[dict]:
    rows = []
    end = START + timedelta(minutes=59)
    for host in WORKSTATIONS:
        t = START + seconds(rng.uniform(0, 90))
        while t < end:
            # Look up a name, then connect to the web server.
            rows.append(connection(t, host, RESOLVER, 53, "udp", "SF", service="dns",
                                   duration=rng.uniform(0.005, 0.06), orig_bytes=rng.randint(30, 60),
                                   resp_bytes=rng.randint(60, 250), history="Dd", orig_pkts=1, resp_pkts=1))
            server = rng.choice(WEB_SERVERS)
            web_at = t + seconds(rng.uniform(0.05, 0.3))
            if rng.random() < 0.85:
                rows.append(connection(web_at, host, server, 443, "tcp", "SF", service="ssl",
                                       duration=rng.uniform(0.4, 45), orig_bytes=rng.randint(600, 6000),
                                       resp_bytes=rng.randint(4000, 250000), history="ShADadFf",
                                       orig_pkts=rng.randint(8, 40), resp_pkts=rng.randint(10, 200)))
            else:
                rows.append(connection(web_at, host, server, 80, "tcp", "SF", service="http",
                                       duration=rng.uniform(0.2, 5), orig_bytes=rng.randint(300, 900),
                                       resp_bytes=rng.randint(1000, 60000), history="ShADadFf",
                                       orig_pkts=rng.randint(5, 12), resp_pkts=rng.randint(5, 50)))
            t += seconds(rng.uniform(120, 300))
        # Each workstation syncs its clock once.
        rows.append(connection(START + seconds(rng.uniform(0, 3000)), host, "198.51.100.123", 123, "udp", "SF",
                               sport=123, service="ntp", duration=rng.uniform(0.01, 0.05),
                               orig_bytes=48, resp_bytes=48, history="Dd", orig_pkts=1, resp_pkts=1))

    # IPv6 multicast DNS: one-way UDP, so Zeek reports S0. This is normal.
    for minute in (5, 25, 45):
        rows.append(connection(START + timedelta(minutes=minute), "2001:db8::10", "2001:db8::fb", 5353, "udp",
                               "S0", sport=5353, service="dns", orig_bytes=60, resp_bytes=0, history="D"))
    # Pings: ICMP echo request (type 8, code 0) stored in the port columns, no history.
    for minute in (3, 18, 33, 48):
        rows.append(connection(START + timedelta(minutes=minute, seconds=7), "192.0.2.13", "198.51.100.1", 0, "icmp",
                               "OTH", sport=8, duration=0.021, orig_bytes=56, resp_bytes=56, orig_pkts=1, resp_pkts=1))
    # An administrator's SSH session to an internal server.
    rows.append(connection(START + timedelta(minutes=12, seconds=40), "192.0.2.10", "192.0.2.25", 22, "tcp", "SF",
                           service="ssh", duration=902.4, orig_bytes=48210, resp_bytes=310455,
                           history="ShADadFf", orig_pkts=620, resp_pkts=710))
    # A single unanswered HTTPS attempt: one failure is normal and below every threshold.
    rows.append(connection(START + timedelta(minutes=27, seconds=3), "192.0.2.15", "198.51.100.50", 443, "tcp",
                           "S0", history="S"))
    # A connection still open when the log was written (S1): Zeek has no final byte counts.
    rows.append(connection(START + timedelta(minutes=58, seconds=30), "192.0.2.12", "198.51.100.31", 443, "tcp",
                           "S1", service="ssl", duration=25.3, history="ShAD", orig_pkts=4, resp_pkts=3))
    return rows


SCAN_PORTS = [1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
              135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543,
              544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
              1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 3389]
assert len(set(SCAN_PORTS)) == 60


def suspicious_traffic() -> list[dict]:
    rows = []

    # 08:10 RDP session from a workstation to a server (watchlisted port, likely admin work).
    rows.append(connection(START + timedelta(minutes=10, seconds=5), "192.0.2.14", "198.51.100.25", 3389, "tcp",
                           "SF", service="rdp", duration=1450.2, orig_bytes=182340, resp_bytes=2409113,
                           history="ShADadFf", orig_pkts=2100, resp_pkts=2600))

    # 08:20 An external host probes 60 ports on one server in about 24 seconds.
    # Closed ports answer with a reset (REJ), filtered ones never answer (S0),
    # open ports (22, 80) answer and the scanner resets them (RSTO).
    ports = SCAN_PORTS[:]
    rng.shuffle(ports)
    scanner_port = ephemeral_port()
    for n, port in enumerate(ports):
        at = START + timedelta(minutes=20) + seconds(n * 0.4)
        if port in (22, 80):
            rows.append(connection(at, "203.0.113.66", "192.0.2.20", port, "tcp", "RSTO", sport=scanner_port,
                                   duration=0.0003, orig_bytes=0, resp_bytes=0, history="ShR", orig_pkts=2, resp_pkts=1))
        elif rng.random() < 0.8:
            rows.append(connection(at, "203.0.113.66", "192.0.2.20", port, "tcp", "REJ", sport=scanner_port,
                                   duration=0.0002, orig_bytes=0, resp_bytes=0, history="Sr", orig_pkts=1, resp_pkts=1))
        else:
            rows.append(connection(at, "203.0.113.66", "192.0.2.20", port, "tcp", "S0", sport=scanner_port,
                                   history="S"))

    # 08:35 One workstation sends 120 DNS queries in under a minute.
    for n in range(120):
        rows.append(connection(START + timedelta(minutes=35) + seconds(n * 0.45), "192.0.2.30", RESOLVER, 53, "udp",
                               "SF", service="dns", duration=rng.uniform(0.004, 0.03), orig_bytes=rng.randint(35, 70),
                               resp_bytes=rng.randint(80, 200), history="Dd", orig_pkts=1, resp_pkts=1))

    # 08:42 Short, regular connections to an external host on port 4444.
    for minute in (42, 47, 52):
        rows.append(connection(START + timedelta(minutes=minute, seconds=10) + seconds(rng.uniform(0, 2)),
                               "192.0.2.12", "203.0.113.80", 4444, "tcp", "SF", duration=rng.uniform(2, 5),
                               orig_bytes=rng.randint(380, 460), resp_bytes=rng.randint(1700, 1900),
                               history="ShADadFf", orig_pkts=6, resp_pkts=6))

    # 08:50 An external host is refused 36 times on SSH in about 53 seconds.
    for n in range(36):
        rows.append(connection(START + timedelta(minutes=50) + seconds(n * 1.5), "203.0.113.99", "192.0.2.26", 22,
                               "tcp", "REJ", duration=0.0002, orig_bytes=0, resp_bytes=0, history="Sr",
                               orig_pkts=1, resp_pkts=1))

    # 08:55 A workstation retries an application server that does not answer, every 5 seconds.
    for n in range(12):
        rows.append(connection(START + timedelta(minutes=55) + seconds(n * 5), "192.0.2.11", "198.51.100.70", 8080,
                               "tcp", "S0", history="S"))
    return rows


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def epoch(at: datetime) -> str:
    return f"{at.timestamp():.6f}"


def tsv_value(name: str, value) -> str:
    if name == "tunnel_parents":
        return "(empty)"
    if value is None:
        return "-"
    if name == "ts":
        return epoch(value)
    if isinstance(value, bool):
        return "T" if value else "F"
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def json_value(name: str, value):
    if name == "ts":
        return float(epoch(value))
    if isinstance(value, float):
        return float(f"{value:.6f}")
    return value


def log_order(rows: list[dict]) -> list[dict]:
    """Zeek writes a connection when it ends, so conn.log is ordered by end time, not start time."""
    return sorted(rows, key=lambda r: (r["ts"] + seconds(r["duration"] or 0), r["uid"]))


def write_tsv(path: Path, rows: list[dict]) -> None:
    lines = [
        "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn",
        f"#open\t{START:%Y-%m-%d-%H-%M-%S}", "#fields\t" + "\t".join(FIELDS), "#types\t" + "\t".join(TYPES),
    ]
    lines += ["\t".join(tsv_value(name, row[name]) for name in FIELDS) for row in rows]
    lines.append(f"#close\t{START + timedelta(hours=1):%Y-%m-%d-%H-%M-%S}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def write_json(path: Path, rows: list[dict]) -> None:
    lines = [json.dumps({name: json_value(name, row[name]) for name in FIELDS if row[name] is not None},
                        separators=(",", ":")) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    normal = normal_traffic()
    demo = log_order(normal + suspicious_traffic())
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    write_tsv(DEMO_DIR / "conn_demo.log", demo)
    write_json(DEMO_DIR / "conn_demo.json", demo)
    write_tsv(FIXTURE_DIR / "normal_traffic.log", log_order(normal))
    print(f"Wrote {len(demo)} demo connections ({len(normal)} normal) to {DEMO_DIR}")
    print(f"Wrote {len(normal)} normal connections to {FIXTURE_DIR / 'normal_traffic.log'}")


if __name__ == "__main__":
    main()
