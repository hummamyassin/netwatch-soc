"""Analyse Zeek connections with pandas: who talked, how much, when, and how it ended.

Usage:
    python -m netwatch.analyzer path/to/conn.log [--top 10]

Where this fits:
    zeek_conn.py   conn.log (TSV or JSON)  -> list of validated ConnRecord
    analyzer.py    ConnRecords             -> pandas DataFrame + statistics   (this file)
    detection.py   DataFrame               -> security alerts

Every analysis function takes the DataFrame made by `records_to_dataframe` and
returns a number, a small dataclass or a small DataFrame. Nothing here knows
about the dashboard, so the same functions serve the CLI, the dashboard and
the tests.

Missing values stay missing: an unknown byte count is <NA>, never 0, and every
total says how many connections actually had a value.
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import sys
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from netwatch.pcap_inspect import positive_limit
from netwatch.zeek_conn import (
    CONN_STATES,
    ConnLogResult,
    ConnRecord,
    ZeekLogError,
    parse_conn_log,
    report_skipped_lines,
)

# Zeek timestamps have microsecond precision, and everything is kept in UTC.
TS_DTYPE = pd.DatetimeTZDtype(unit="us", tz="UTC")

COLUMNS = [
    "event_id", "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state", "history",
    "icmp_type", "icmp_code",
]
TEXT_COLUMNS = ["uid", "src_ip", "dst_ip", "proto", "service", "conn_state", "history"]
COUNT_COLUMNS = ["src_port", "dst_port", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                 "icmp_type", "icmp_code"]

NOT_RECORDED = "(not recorded)"  # label used when Zeek left a field empty
DEFAULT_TOP = 10

# Bucket sizes tried for "connections over time", smallest first.
TIME_BUCKETS = [
    (1, "1s"), (5, "5s"), (10, "10s"), (30, "30s"), (60, "1min"), (300, "5min"),
    (900, "15min"), (1800, "30min"), (3600, "1h"), (6 * 3600, "6h"), (86400, "1D"), (7 * 86400, "7D"),
]
MAX_TIME_BUCKETS = 60


# ---------------------------------------------------------------------------
# From parsed records to a DataFrame
# ---------------------------------------------------------------------------

def event_id_for(record: ConnRecord, position: int) -> str:
    """A stable reference to one connection.

    Zeek's uid when present (it also links conn.log to dns.log, http.log, ...).
    Otherwise 'row-N', where N is the record's position in the parsed log.
    """
    return record.uid if record.uid else f"row-{position}"


def records_to_dataframe(records: list[ConnRecord]) -> pd.DataFrame:
    """One row per connection, with fixed column types.

    ts                         datetime64[us, UTC]
    ports, bytes, packets      Int64   (pandas' integer type that allows <NA>)
    duration                   Float64
    text columns, event_id     object  (None when missing)
    """
    columns = {
        "event_id": pd.Series([event_id_for(r, n) for n, r in enumerate(records, start=1)], dtype="object"),
        "ts": pd.Series([r.ts for r in records], dtype=TS_DTYPE),
        "duration": pd.Series([r.duration for r in records], dtype="Float64"),
    }
    for name in TEXT_COLUMNS:
        columns[name] = pd.Series([getattr(r, name) for r in records], dtype="object")
    for name in COUNT_COLUMNS:
        columns[name] = pd.Series([getattr(r, name) for r in records], dtype="Int64")
    return pd.DataFrame(columns)[COLUMNS]


def drop_duplicate_events(frame: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Remove repeated connections (same Zeek uid), keeping the first one.

    A uid appears twice when, for example, a log was appended to itself.
    Counting it twice would inflate every statistic and alert.
    Returns (frame without repeats, number removed).
    """
    repeated = frame["event_id"].duplicated(keep="first")
    return frame.loc[~repeated].reset_index(drop=True), int(repeated.sum())


@dataclass
class LoadedLog:
    result: ConnLogResult          # parser output: format and skipped-line messages
    connections: pd.DataFrame      # one row per unique connection
    duplicates_removed: int        # repeated uids that were dropped


def build_loaded_log(result: ConnLogResult) -> LoadedLog:
    frame, removed = drop_duplicate_events(records_to_dataframe(result.records))
    return LoadedLog(result=result, connections=frame, duplicates_removed=removed)


def load_log(path: str | Path) -> LoadedLog:
    """Parse a conn.log file and build its DataFrame. Raises ZeekLogError."""
    return build_loaded_log(parse_conn_log(path))


# ---------------------------------------------------------------------------
# Helpers for counting and sorting
# ---------------------------------------------------------------------------

def ip_sort_key(ip: str) -> str:
    """Sort key that orders IPs numerically (10.0.0.2 before 10.0.0.10), IPv4 before IPv6."""
    address = ipaddress.ip_address(ip)
    return f"{address.version}-{int(address):039d}"


def _labels(values: pd.Series) -> pd.Series:
    """Text labels where a missing value becomes NOT_RECORDED."""
    as_text = values.astype("object")
    return as_text.where(as_text.notna(), NOT_RECORDED)


def _count_table(values: pd.Series, column: str) -> pd.DataFrame:
    return values.value_counts().rename_axis(column).reset_index(name="connections")


def _percent(counts: pd.Series, total: int) -> pd.Series:
    return (counts * 100 / total).round(1) if total else counts.astype("float64")


def _sort_by_count(table: pd.DataFrame, tie_breakers: list[str]) -> pd.DataFrame:
    """Most connections first. Ties are broken by the given columns, ascending,
    so the same data always gives the same order."""
    return table.sort_values(
        ["connections", *tie_breakers],
        ascending=[False] + [True] * len(tie_breakers),
        kind="mergesort",
    ).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def total_connections(frame: pd.DataFrame) -> int:
    return len(frame)


def unique_source_ips(frame: pd.DataFrame) -> int:
    return int(frame["src_ip"].nunique())


def unique_destination_ips(frame: pd.DataFrame) -> int:
    return int(frame["dst_ip"].nunique())


def time_range(frame: pd.DataFrame) -> tuple[pd.Timestamp, pd.Timestamp] | None:
    """(first, last) connection start time in UTC, or None for an empty log."""
    if frame.empty:
        return None
    return frame["ts"].min(), frame["ts"].max()


def protocol_distribution(frame: pd.DataFrame) -> pd.DataFrame:
    """Connections per transport protocol (tcp, udp, icmp, ...), most common first.

    Columns: proto, connections, percent.
    """
    table = _count_table(_labels(frame["proto"]), "proto")
    table["percent"] = _percent(table["connections"], len(frame))
    return _sort_by_count(table, ["proto"])


def top_source_ips(frame: pd.DataFrame, n: int = DEFAULT_TOP) -> pd.DataFrame:
    """The n source IPs that started the most connections.

    Columns: src_ip, connections. Ties: lower IP address first.
    """
    table = _count_table(frame["src_ip"].astype("object"), "src_ip")
    table = table.assign(_ip_key=table["src_ip"].map(ip_sort_key))
    return _sort_by_count(table, ["_ip_key"]).drop(columns="_ip_key").head(n).reset_index(drop=True)


def top_destination_ports(frame: pd.DataFrame, n: int = DEFAULT_TOP) -> pd.DataFrame:
    """The n most contacted destination ports, counted per protocol.

    53/udp (DNS queries) and 53/tcp are different services, so they are
    counted separately. ICMP has no ports and is not counted here.
    Columns: dst_port, proto, connections. Ties: lower port first.
    """
    with_port = frame.loc[frame["dst_port"].notna()]
    pairs = pd.DataFrame({"dst_port": with_port["dst_port"], "proto": _labels(with_port["proto"])})
    table = pairs.groupby(["dst_port", "proto"]).size().reset_index(name="connections")
    return _sort_by_count(table, ["dst_port", "proto"]).head(n).reset_index(drop=True)


def describe_state(state: str) -> str:
    if state == NOT_RECORDED:
        return "Zeek did not record a state"
    return CONN_STATES.get(state, "Unknown state")


def has_connection_states(frame: pd.DataFrame) -> bool:
    return bool(frame["conn_state"].notna().any())


def connection_state_distribution(frame: pd.DataFrame) -> pd.DataFrame:
    """Connections per Zeek conn_state (SF, S0, REJ, ...), most common first.

    Columns: conn_state, description, connections, percent.
    """
    table = _count_table(_labels(frame["conn_state"]), "conn_state")
    table["description"] = table["conn_state"].map(describe_state)
    table["percent"] = _percent(table["connections"], len(frame))
    return _sort_by_count(table, ["conn_state"])[["conn_state", "description", "connections", "percent"]]


@dataclass(frozen=True)
class ByteTotals:
    orig_bytes: int              # payload bytes sent by originators (known values only)
    resp_bytes: int              # payload bytes sent by responders (known values only)
    connections_with_orig: int   # connections where orig_bytes was recorded
    connections_with_resp: int   # connections where resp_bytes was recorded
    connections: int

    @property
    def total(self) -> int:
        return self.orig_bytes + self.resp_bytes


def byte_totals(frame: pd.DataFrame) -> ByteTotals:
    """Total transferred payload bytes, counting only values Zeek recorded.

    A missing byte count is not a zero-byte transfer, so it is left out of the
    sum, and connections_with_* says how many connections were included.
    """
    orig, resp = frame["orig_bytes"], frame["resp_bytes"]
    return ByteTotals(
        orig_bytes=int(orig.sum()),
        resp_bytes=int(resp.sum()),
        connections_with_orig=int(orig.notna().sum()),
        connections_with_resp=int(resp.notna().sum()),
        connections=len(frame),
    )


@dataclass(frozen=True)
class DurationStats:
    average_seconds: float | None    # None when no connection has a duration
    connections_with_duration: int
    connections: int


def duration_stats(frame: pd.DataFrame) -> DurationStats:
    """Average connection duration over the connections that have one."""
    known = frame["duration"].dropna()
    average = float(known.mean()) if len(known) else None
    return DurationStats(average, len(known), len(frame))


def choose_time_bucket(span_seconds: float, max_buckets: int = MAX_TIME_BUCKETS) -> str:
    """Pick the smallest bucket size that splits the time span into at most max_buckets."""
    for seconds, alias in TIME_BUCKETS:
        if span_seconds / seconds <= max_buckets:
            return alias
    return f"{math.ceil(span_seconds / max_buckets)}s"


def connections_over_time(frame: pd.DataFrame, bucket: str | None = None) -> tuple[pd.DataFrame, str]:
    """Connections started per time bucket, in UTC.

    Quiet periods inside the time range are included with 0 connections, so a
    chart shows gaps honestly. Returns (DataFrame with columns time and
    connections, bucket size used, e.g. "5min").
    """
    if bucket is None:
        span = 0.0 if frame.empty else (frame["ts"].max() - frame["ts"].min()).total_seconds()
        bucket = choose_time_bucket(span)
    if frame.empty:
        empty = pd.DataFrame({"time": pd.Series(dtype=TS_DTYPE), "connections": pd.Series(dtype="int64")})
        return empty, bucket
    counts = frame.set_index("ts").resample(bucket).size()
    return counts.rename_axis("time").reset_index(name="connections"), bucket


# ---------------------------------------------------------------------------
# Text report for the command line
# ---------------------------------------------------------------------------

def human_bytes(count: int) -> str:
    """1536 -> '1.5 KB' (1 KB = 1024 bytes)."""
    size = float(count)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024 or unit == "GB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # not reached


def human_span(seconds: float) -> str:
    """3725 -> '1h 02m 05s'; 5.8 -> '5.8 s'."""
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(round(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s" if hours else f"{minutes}m {secs:02d}s"


def format_ts(value) -> str:
    """'2025-03-10 08:20:00 UTC' for a UTC datetime or pandas Timestamp; '-' when missing.

    Used for every timestamp the project shows (CLI reports, alerts, dashboard).
    """
    if value is None or pd.isna(value):
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_report(loaded: LoadedLog, top: int = DEFAULT_TOP) -> str:
    frame = loaded.connections
    lines = [
        f"File:            {loaded.result.path}",
        f"Format:          Zeek {loaded.result.log_format.upper()}",
        f"Connections:     {total_connections(frame)} "
        f"({len(loaded.result.errors)} line(s) skipped, {loaded.duplicates_removed} duplicate(s) removed)",
    ]
    if frame.empty:
        lines.append("\nNo connections to analyse.")
        return "\n".join(lines)

    first, last = time_range(frame)
    bytes_ = byte_totals(frame)
    durations = duration_stats(frame)
    average = "not recorded" if durations.average_seconds is None else f"{durations.average_seconds:.3f} s"
    lines += [
        f"Time range:      {format_ts(first)} -> {format_ts(last)} ({human_span((last - first).total_seconds())})",
        f"Source IPs:      {unique_source_ips(frame)} unique",
        f"Destination IPs: {unique_destination_ips(frame)} unique",
        f"Bytes sent:      {human_bytes(bytes_.orig_bytes)} by originators "
        f"({bytes_.connections_with_orig} of {bytes_.connections} connections recorded), "
        f"{human_bytes(bytes_.resp_bytes)} by responders "
        f"({bytes_.connections_with_resp} of {bytes_.connections} recorded)",
        f"Avg duration:    {average} "
        f"({durations.connections_with_duration} of {durations.connections} connections recorded)",
    ]

    sections = [
        ("Protocols", protocol_distribution(frame)),
        (f"Top {top} source IPs", top_source_ips(frame, top)),
        (f"Top {top} destination ports", top_destination_ports(frame, top)),
        ("Connection states", connection_state_distribution(frame)),
    ]
    for title, table in sections:
        lines += ["", title, table.to_string(index=False) if not table.empty else "  (none)"]

    timeline, bucket = connections_over_time(frame)
    peak = int(timeline["connections"].max())
    lines += ["", f"Connections over time ({bucket} buckets, UTC)"]
    for row in timeline.itertuples(index=False):
        bar = "#" * math.ceil(40 * row.connections / peak) if row.connections else ""
        lines.append(f"  {row.time.strftime('%Y-%m-%d %H:%M:%S')}  {row.connections:>6}  {bar}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m netwatch.analyzer",
        description="Summarise a Zeek conn.log (TSV or JSON) with pandas.",
    )
    parser.add_argument("log", help="path to a Zeek conn.log file")
    parser.add_argument("-t", "--top", type=positive_limit, default=DEFAULT_TOP,
                        help=f"rows in each top-N table (default {DEFAULT_TOP})")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        loaded = load_log(args.log)
    except ZeekLogError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    errors = loaded.result.errors
    report_skipped_lines(errors)

    print(format_report(loaded, args.top))
    if loaded.connections.empty and errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
