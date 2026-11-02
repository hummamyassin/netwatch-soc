"""Rule-based detection: turn Zeek connections into explainable security alerts.

Usage:
    python -m netwatch.detection path/to/conn.log [--scan-ports 15] [--rules NW-001,NW-003] ...

How it works:
    Each rule is a small, deterministic function over the connections
    DataFrame from analyzer.py. The same log with the same configuration
    always gives the same alerts, with the same alert IDs. No machine learning
    or AI is involved: every alert can be traced back to log lines and to the
    thresholds in DetectionConfig.

Wording matters:
    An alert describes *possible* suspicious behaviour that deserves an
    analyst's attention. It is not proof of an attack. Every rule lists
    common false positives (RULES below and docs/DETECTION_RULES.md).

Rules:
    NW-001  Possible Port Scan            many distinct ports on one host in a short window
    NW-002  High Connection Rate          many connections from one source in a short window
    NW-003  Suspicious Destination Port   traffic to a watchlisted port (contextual)
    NW-004  Repeated Failed Connections   many rejected/unanswered TCP attempts to one service
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import textwrap
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

import pandas as pd

from netwatch.analyzer import ip_sort_key, load_log
from netwatch.zeek_conn import MAX_ERRORS_SHOWN, ZeekLogError

SEVERITIES = ("Low", "Medium", "High")  # least to most severe

# Zeek TCP states that mean "the connection attempt failed":
#   S0      attempt seen, no reply at all
#   REJ     attempt rejected (the target answered with a reset: port closed)
#   RSTOS0  originator sent SYN then RST, never got a SYN-ACK
#   SH      originator sent SYN then FIN, never got a SYN-ACK
# Normal states (SF, S1, RSTO, ...) and *missing* states are never treated as failures.
# UDP is excluded: one-way UDP (state S0) is normal for mDNS, syslog, NTP broadcasts...
FAILED_TCP_STATES = frozenset({"S0", "REJ", "RSTOS0", "SH"})

# Ports worth a second look when traffic reaches them. A match is context for
# an analyst, not evidence of wrongdoing.
DEFAULT_WATCHLIST = {
    23: "Telnet, unencrypted remote login",
    3389: "RDP remote desktop, a common brute-force target",
    4444: "default listener port of some exploit frameworks",
    5900: "VNC remote desktop",
    6667: "IRC, historically used for botnet command and control",
    31337: "historically used by backdoors",
}

MAX_WINDOW_SECONDS = 7 * 24 * 3600
MAX_THRESHOLD = 1_000_000


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str                       # shown to analysts as the alert type
    base_severity: str
    description: str
    false_positives: tuple[str, ...]


RULES = {
    "NW-001": Rule(
        "NW-001", "Possible Port Scan", "Medium",
        "One source contacts many different destination ports on the same host within a short time window.",
        ("Vulnerability scanners or inventory tools run by the IT team",
         "Monitoring systems that check many services on one server",
         "Applications that use many ports, e.g. passive FTP or Windows RPC"),
    ),
    "NW-002": Rule(
        "NW-002", "High Connection Rate", "Low",
        "One source starts more connections than the threshold within a short time window.",
        ("Busy servers, proxies or NAT gateways that act for many users",
         "Backup, update or software-distribution jobs",
         "Chatty or misconfigured applications, e.g. a DNS client retrying constantly"),
    ),
    "NW-003": Rule(
        "NW-003", "Suspicious Destination Port", "Low",
        "Traffic reached a destination port on the watchlist (rejected or unanswered TCP attempts are not counted).",
        ("Legitimate use of the service, e.g. administrators using RDP or VNC",
         "Software that happens to use a watchlisted port number",
         "Approved security testing"),
    ),
    "NW-004": Rule(
        "NW-004", "Repeated Failed Connections", "Medium",
        "One source keeps trying to reach the same TCP service, but the attempts are rejected or unanswered.",
        ("A client retrying a server that is down, moved or overloaded",
         "A misconfigured application pointing at the wrong host or port",
         "A firewall change that silently drops traffic"),
    ),
}


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds for every rule.

    The defaults are demonstration values that suit the bundled demo data and
    small labs. Real networks need tuning (see docs/DETECTION_RULES.md).
    """

    port_scan_min_ports: int = 15          # NW-001: distinct ports on one target...
    port_scan_window_seconds: int = 60     # ...within this many seconds
    high_rate_min_connections: int = 100   # NW-002: connections from one source...
    high_rate_window_seconds: int = 60     # ...within this many seconds
    watchlist_ports: tuple[int, ...] = tuple(sorted(DEFAULT_WATCHLIST))  # NW-003
    failed_min_attempts: int = 10          # NW-004: failed TCP attempts to one service...
    failed_window_seconds: int = 60        # ...within this many seconds
    escalation_factor: int = 3             # severity +1 level at factor x threshold
    enabled_rules: tuple[str, ...] = tuple(RULES)

    def validate(self) -> None:
        """Raise ValueError with a clear message if a setting makes no sense."""
        whole_numbers = {
            "port_scan_min_ports": (self.port_scan_min_ports, MAX_THRESHOLD),
            "high_rate_min_connections": (self.high_rate_min_connections, MAX_THRESHOLD),
            "failed_min_attempts": (self.failed_min_attempts, MAX_THRESHOLD),
            "port_scan_window_seconds": (self.port_scan_window_seconds, MAX_WINDOW_SECONDS),
            "high_rate_window_seconds": (self.high_rate_window_seconds, MAX_WINDOW_SECONDS),
            "failed_window_seconds": (self.failed_window_seconds, MAX_WINDOW_SECONDS),
        }
        for name, (value, maximum) in whole_numbers.items():
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be a whole number from 1 to {maximum}, got {value!r}")
        if isinstance(self.escalation_factor, bool) or not isinstance(self.escalation_factor, int) \
                or self.escalation_factor < 2:
            raise ValueError(f"escalation_factor must be a whole number of at least 2, got {self.escalation_factor!r}")
        for port in self.watchlist_ports:
            if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
                raise ValueError(f"watchlist ports must be whole numbers from 0 to 65535, got {port!r}")
        unknown = [rule_id for rule_id in self.enabled_rules if rule_id not in RULES]
        if unknown:
            raise ValueError(f"unknown rule ID(s): {', '.join(map(str, unknown))}")


@dataclass(frozen=True)
class Alert:
    alert_id: str                  # stable: same data + same configuration -> same ID
    rule_id: str
    alert_type: str
    severity: str                  # "High", "Medium" or "Low"
    src_ip: str
    dst_ip: str | None             # None when several destinations are involved
    dst_ports: tuple[int, ...]     # distinct destination ports, ascending (empty if none recorded)
    protocols: tuple[str, ...]     # distinct protocols, ascending (empty if none recorded)
    first_seen: datetime           # UTC
    last_seen: datetime            # UTC
    connection_count: int          # supporting connections
    destination_count: int         # distinct destination IPs
    observed_value: int            # what the rule measured (the peak inside one window)
    threshold: int
    window_seconds: int | None     # None when the rule uses no time window (NW-003)
    explanation: str
    event_ids: tuple[str, ...]     # supporting connections (Zeek uid or row-N), in time order


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Episode:
    first: int   # position of the first supporting event (in time-sorted order)
    last: int    # position of the last supporting event
    peak: int    # highest value measured inside a single window


def find_episodes(times: list, keys: list | None, window_seconds: int, threshold: int) -> list[Episode]:
    """Slide a time window over time-sorted events and return the bursts that reach the threshold.

    For each event, the window holds that event and every earlier event that is
    at most `window_seconds` older (inclusive). The measured value is the number
    of events in the window, or, when `keys` is given, the number of *distinct*
    keys (for example distinct ports).

    Windows that reach the threshold and share events are merged into one
    episode, so one long burst gives one alert, not one alert per window.
    A quiet gap longer than the window starts a new episode.
    """
    window = timedelta(seconds=window_seconds)
    keys_in_window: Counter = Counter()
    start = 0
    episodes: list[list[int]] = []  # [first, last, peak]
    for end in range(len(times)):
        if keys is not None:
            keys_in_window[keys[end]] += 1
        while times[end] - times[start] > window:
            if keys is not None:
                keys_in_window[keys[start]] -= 1
                if keys_in_window[keys[start]] == 0:
                    del keys_in_window[keys[start]]
            start += 1
        value = len(keys_in_window) if keys is not None else end - start + 1
        if value < threshold:
            continue
        if episodes and start <= episodes[-1][1]:   # overlaps the previous burst: extend it
            episodes[-1][1] = end
            episodes[-1][2] = max(episodes[-1][2], value)
        else:
            episodes.append([start, end, value])
    return [Episode(first, last, peak) for first, last, peak in episodes]


def escalate(base: str, observed: int, threshold: int, factor: int) -> str:
    """Raise the severity one level when the observed value is at least factor x threshold."""
    level = SEVERITIES.index(base)
    if observed >= threshold * factor:
        level = min(level + 1, len(SEVERITIES) - 1)
    return SEVERITIES[level]


def is_failed_tcp_attempt(frame: pd.DataFrame) -> pd.Series:
    """True for TCP connections whose state shows the attempt failed (see FAILED_TCP_STATES)."""
    return (frame["proto"] == "tcp") & frame["conn_state"].isin(FAILED_TCP_STATES)


def make_alert_id(rule_id: str, src_ip: str, dst_ip: str | None, first_seen: datetime,
                  last_seen: datetime, event_ids: tuple[str, ...]) -> str:
    """Fingerprint of what the alert is about: same rule + same supporting events -> same ID."""
    fingerprint = "|".join([rule_id, src_ip, dst_ip or "-", first_seen.isoformat(), last_seen.isoformat(), *event_ids])
    return f"{rule_id}-{hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()[:12]}"


def format_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def count_text(values: pd.Series) -> str:
    """'REJ=36, S0=2' style summary (most common first, ties alphabetical), or 'not recorded'."""
    counts = values.dropna().value_counts()
    pairs = sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))
    return ", ".join(f"{value}={count}" for value, count in pairs) or "not recorded"


def _alert_from_events(rule_id: str, events: pd.DataFrame, *, severity: str, observed: int, threshold: int,
                       window_seconds: int | None, explanation: str) -> Alert:
    """Build an Alert from its supporting events. Only values present in the log are used."""
    src_ip = str(events["src_ip"].iloc[0])
    dst_ips = sorted(events["dst_ip"].dropna().unique(), key=ip_sort_key)
    first_seen = events["ts"].min().to_pydatetime()
    last_seen = events["ts"].max().to_pydatetime()
    event_ids = tuple(events["event_id"])
    dst_ip = str(dst_ips[0]) if len(dst_ips) == 1 else None
    return Alert(
        alert_id=make_alert_id(rule_id, src_ip, dst_ip, first_seen, last_seen, event_ids),
        rule_id=rule_id,
        alert_type=RULES[rule_id].name,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_ports=tuple(sorted(int(port) for port in events["dst_port"].dropna().unique())),
        protocols=tuple(sorted(str(proto) for proto in events["proto"].dropna().unique())),
        first_seen=first_seen,
        last_seen=last_seen,
        connection_count=len(events),
        destination_count=len(dst_ips),
        observed_value=observed,
        threshold=threshold,
        window_seconds=window_seconds,
        explanation=explanation,
        event_ids=event_ids,
    )


def _seen(events: pd.DataFrame) -> str:
    first, last = events["ts"].min(), events["ts"].max()
    return f"from {format_time(first)} to {format_time(last)}"


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------

def detect_port_scans(frame: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NW-001: one source, one target, many distinct ports within the window (per protocol)."""
    rule, window, threshold = RULES["NW-001"], config.port_scan_window_seconds, config.port_scan_min_ports
    rows = frame.loc[frame["proto"].isin(["tcp", "udp"]) & frame["dst_port"].notna()]
    alerts = []
    for (src, dst, proto), group in rows.groupby(["src_ip", "dst_ip", "proto"], sort=True):
        for episode in find_episodes(group["ts"].tolist(), group["dst_port"].tolist(), window, threshold):
            events = group.iloc[episode.first:episode.last + 1]
            explanation = (
                f"{src} contacted {episode.peak} different {proto.upper()} ports on {dst} within {window} s "
                f"(threshold: {threshold} ports within {window} s). {len(events)} connections {_seen(events)}; "
                f"connection states: {count_text(events['conn_state'])}. This pattern can indicate a port scan "
                f"(reconnaissance), but authorised scanners and some applications behave the same way."
            )
            alerts.append(_alert_from_events(
                rule.rule_id, events, observed=episode.peak, threshold=threshold, window_seconds=window,
                severity=escalate(rule.base_severity, episode.peak, threshold, config.escalation_factor),
                explanation=explanation))
    return alerts


def detect_high_connection_rates(frame: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NW-002: one source starts at least the threshold number of connections within the window."""
    rule, window, threshold = RULES["NW-002"], config.high_rate_window_seconds, config.high_rate_min_connections
    alerts = []
    for src, group in frame.groupby("src_ip", sort=True):
        for episode in find_episodes(group["ts"].tolist(), None, window, threshold):
            events = group.iloc[episode.first:episode.last + 1]
            destinations = events["dst_ip"].value_counts()
            busiest = sorted(destinations.items(), key=lambda item: (-item[1], ip_sort_key(item[0])))[0]
            protocols = ", ".join(sorted(events["proto"].dropna().unique())) or "not recorded"
            explanation = (
                f"{src} started {episode.peak} connections within {window} s "
                f"(threshold: {threshold} connections within {window} s). {len(events)} connections "
                f"{_seen(events)} to {len(destinations)} destination(s), most often {busiest[0]} "
                f"({busiest[1]} connections); protocols: {protocols}. A high rate can come from scanning, "
                f"flooding or malware, but also from busy servers, proxies, backups or chatty applications."
            )
            alerts.append(_alert_from_events(
                rule.rule_id, events, observed=episode.peak, threshold=threshold, window_seconds=window,
                severity=escalate(rule.base_severity, episode.peak, threshold, config.escalation_factor),
                explanation=explanation))
    return alerts


def detect_watchlist_ports(frame: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NW-003: traffic to a watchlisted destination port. One alert per source, target, port and protocol."""
    rule = RULES["NW-003"]
    rows = frame.loc[frame["dst_port"].isin(set(config.watchlist_ports)) & ~is_failed_tcp_attempt(frame)]
    rows = rows.assign(_proto=rows["proto"].where(rows["proto"].notna(), ""))
    alerts = []
    for (src, dst, port, proto), events in rows.groupby(["src_ip", "dst_ip", "dst_port", "_proto"], sort=True):
        port = int(port)
        service = DEFAULT_WATCHLIST.get(port, "custom watchlist entry")
        port_text = f"{port}/{proto}" if proto else f"{port} (protocol not recorded)"
        explanation = (
            f"{src} reached {dst} on watchlisted port {port_text} ({service}) {len(events)} time(s) "
            f"{_seen(events)}; connection states: {count_text(events['conn_state'])}. This is a contextual "
            f"observation, not evidence of malicious activity: the service may be used legitimately. "
            f"Rejected or unanswered TCP attempts are not counted here (see NW-001 and NW-004)."
        )
        alerts.append(_alert_from_events(
            rule.rule_id, events.drop(columns="_proto"), observed=len(events), threshold=1, window_seconds=None,
            severity=rule.base_severity, explanation=explanation))
    return alerts


def detect_repeated_failures(frame: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NW-004: many failed TCP attempts from one source to the same host and port within the window."""
    rule, window, threshold = RULES["NW-004"], config.failed_window_seconds, config.failed_min_attempts
    failed = frame.loc[is_failed_tcp_attempt(frame) & frame["dst_port"].notna()]
    alerts = []
    for (src, dst, port), group in failed.groupby(["src_ip", "dst_ip", "dst_port"], sort=True):
        for episode in find_episodes(group["ts"].tolist(), None, window, threshold):
            events = group.iloc[episode.first:episode.last + 1]
            explanation = (
                f"{src} made {episode.peak} failed TCP connection attempts to {dst}:{int(port)} within {window} s "
                f"(threshold: {threshold} failed attempts within {window} s). {len(events)} failed attempts "
                f"{_seen(events)}; connection states: {count_text(events['conn_state'])} "
                f"(S0 = no reply, REJ = rejected). Possible causes include automated login or exploitation "
                f"attempts, but also a client retrying a server that is down or misconfigured."
            )
            alerts.append(_alert_from_events(
                rule.rule_id, events, observed=episode.peak, threshold=threshold, window_seconds=window,
                severity=escalate(rule.base_severity, episode.peak, threshold, config.escalation_factor),
                explanation=explanation))
    return alerts


RULE_FUNCTIONS = {
    "NW-001": detect_port_scans,
    "NW-002": detect_high_connection_rates,
    "NW-003": detect_watchlist_ports,
    "NW-004": detect_repeated_failures,
}

REQUIRED_COLUMNS = ("event_id", "ts", "src_ip", "dst_ip", "dst_port", "proto", "conn_state")


def prepare_connections(connections: pd.DataFrame) -> pd.DataFrame:
    """Sort by time (ties by event_id) and drop repeated events, so input order never matters."""
    missing = [column for column in REQUIRED_COLUMNS if column not in connections.columns]
    if missing:
        raise ValueError(f"connections table is missing column(s): {', '.join(missing)}")
    ordered = connections.sort_values(["ts", "event_id"], kind="mergesort")
    return ordered.drop_duplicates(subset="event_id", keep="first").reset_index(drop=True)


def run_detection(connections: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    """Run every enabled rule and return alerts sorted by first_seen, then rule and ID."""
    config = config or DetectionConfig()
    config.validate()
    frame = prepare_connections(connections)
    alerts: list[Alert] = []
    for rule_id, detect in RULE_FUNCTIONS.items():
        if rule_id in config.enabled_rules:
            alerts.extend(detect(frame, config))
    unique = {alert.alert_id: alert for alert in alerts}  # equivalent detections collapse into one
    return sorted(unique.values(), key=lambda a: (a.first_seen, a.rule_id, a.alert_id))


def severity_counts(alerts: list[Alert]) -> dict[str, int]:
    """{'High': n, 'Medium': n, 'Low': n}, most severe first."""
    counts = Counter(alert.severity for alert in alerts)
    return {severity: counts.get(severity, 0) for severity in reversed(SEVERITIES)}


def parse_port_list(text: str) -> tuple[int, ...]:
    """'23, 3389,4444' -> (23, 3389, 4444). Raises ValueError for anything that is not a port."""
    ports = set()
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or not 0 <= int(part) <= 65535:
            raise ValueError(f"not a valid port number: {part!r}")
        ports.add(int(part))
    return tuple(sorted(ports))


def describe_config(config: DetectionConfig) -> list[str]:
    """One human-readable line per enabled rule."""
    lines = {
        "NW-001": f"NW-001 Possible Port Scan: >= {config.port_scan_min_ports} distinct ports on one host "
                  f"within {config.port_scan_window_seconds} s",
        "NW-002": f"NW-002 High Connection Rate: >= {config.high_rate_min_connections} connections from one "
                  f"source within {config.high_rate_window_seconds} s",
        "NW-003": "NW-003 Suspicious Destination Port: watchlist "
                  + (", ".join(map(str, config.watchlist_ports)) or "(empty)"),
        "NW-004": f"NW-004 Repeated Failed Connections: >= {config.failed_min_attempts} failed TCP attempts "
                  f"to one service within {config.failed_window_seconds} s",
    }
    return [line for rule_id, line in lines.items() if rule_id in config.enabled_rules]


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def format_alert(number: int, alert: Alert, max_events: int = 5) -> str:
    ports = ", ".join(map(str, alert.dst_ports[:15])) + (" ..." if len(alert.dst_ports) > 15 else "")
    events = ", ".join(alert.event_ids[:max_events])
    if len(alert.event_ids) > max_events:
        events += f" ... (+{len(alert.event_ids) - max_events} more)"
    window = f"{alert.window_seconds} s" if alert.window_seconds else "whole log"
    indent = " " * 18
    wrapped = textwrap.fill(alert.explanation, width=100, initial_indent=indent, subsequent_indent=indent)[18:]
    return "\n".join([
        f"[{number}] {alert.severity.upper():<6} {alert.rule_id} {alert.alert_type}   ({alert.alert_id})",
        f"    Source:       {alert.src_ip}",
        f"    Destination:  {alert.dst_ip or f'{alert.destination_count} different hosts'}",
        f"    Protocol:     {', '.join(alert.protocols) or 'not recorded'}"
        f"   Ports ({len(alert.dst_ports)}): {ports or 'none recorded'}",
        f"    Seen:         {format_time(alert.first_seen)} -> {format_time(alert.last_seen)}"
        f" ({alert.connection_count} connection(s))",
        f"    Measured:     {alert.observed_value} (threshold {alert.threshold}, window {window})",
        f"    Why:          {wrapped}",
        f"    Events:       {events}",
    ])


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a whole number, got {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {number}")
    return number


def port_list(value: str) -> tuple[int, ...]:
    try:
        return parse_port_list(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def rule_list(value: str) -> tuple[str, ...]:
    rules = tuple(part.strip().upper() for part in value.split(",") if part.strip())
    unknown = [rule for rule in rules if rule not in RULES]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown rule ID(s): {', '.join(unknown)} (known: {', '.join(RULES)})")
    return rules


def build_arg_parser() -> argparse.ArgumentParser:
    defaults = DetectionConfig()
    parser = argparse.ArgumentParser(
        prog="python -m netwatch.detection",
        description="Run NetWatch SOC's deterministic detection rules on a Zeek conn.log (TSV or JSON).",
    )
    parser.add_argument("log", help="path to a Zeek conn.log file")
    parser.add_argument("--scan-ports", type=positive_int, default=defaults.port_scan_min_ports,
                        help="NW-001: distinct ports on one host (default %(default)s)")
    parser.add_argument("--scan-window", type=positive_int, default=defaults.port_scan_window_seconds,
                        help="NW-001: window in seconds (default %(default)s)")
    parser.add_argument("--rate-connections", type=positive_int, default=defaults.high_rate_min_connections,
                        help="NW-002: connections from one source (default %(default)s)")
    parser.add_argument("--rate-window", type=positive_int, default=defaults.high_rate_window_seconds,
                        help="NW-002: window in seconds (default %(default)s)")
    parser.add_argument("--watchlist", type=port_list, default=defaults.watchlist_ports,
                        help="NW-003: comma-separated ports (default: "
                             + ",".join(map(str, defaults.watchlist_ports)) + ")")
    parser.add_argument("--failed-attempts", type=positive_int, default=defaults.failed_min_attempts,
                        help="NW-004: failed TCP attempts to one service (default %(default)s)")
    parser.add_argument("--failed-window", type=positive_int, default=defaults.failed_window_seconds,
                        help="NW-004: window in seconds (default %(default)s)")
    parser.add_argument("--rules", type=rule_list, default=defaults.enabled_rules,
                        help="comma-separated rule IDs to run (default: all)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = DetectionConfig(
        port_scan_min_ports=args.scan_ports, port_scan_window_seconds=args.scan_window,
        high_rate_min_connections=args.rate_connections, high_rate_window_seconds=args.rate_window,
        watchlist_ports=args.watchlist, failed_min_attempts=args.failed_attempts,
        failed_window_seconds=args.failed_window, enabled_rules=args.rules,
    )
    try:
        config.validate()
        loaded = load_log(args.log)
    except (ValueError, ZeekLogError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    errors = loaded.result.errors
    if errors:
        print(f"Warning: skipped {len(errors)} line(s) that could not be parsed:", file=sys.stderr)
        for message in errors[:MAX_ERRORS_SHOWN]:
            print(f"  {message}", file=sys.stderr)
        print(file=sys.stderr)

    alerts = run_detection(loaded.connections, config)
    counts = severity_counts(alerts)
    print(f"File:    {loaded.result.path}")
    print(f"Log:     Zeek {loaded.result.log_format.upper()}, {len(loaded.connections)} connection(s), "
          f"{len(errors)} line(s) skipped, {loaded.duplicates_removed} duplicate(s) removed")
    print("Rules:   " + "\n         ".join(describe_config(config)))
    print(f"Alerts:  {len(alerts)} (High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']})")
    if not alerts:
        print("\nNo alerts: nothing in this log reached a rule threshold.")
    for number, alert in enumerate(alerts, start=1):
        print()
        print(format_alert(number, alert))
    print("\nAlerts describe possible suspicious behaviour that needs review, not confirmed attacks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
