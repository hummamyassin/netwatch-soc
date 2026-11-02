"""Read a Zeek conn.log (TSV or JSON) and turn each connection into a clean record.

Usage:
    python -m netwatch.zeek_conn path/to/conn.log [--limit 20]

What is conn.log?
    Zeek reads traffic (for example `zeek -C -r capture.pcap`) and writes one
    line per network *connection* to conn.log: who talked to whom, on which
    ports and protocol, for how long, how many bytes and packets were sent,
    and how the connection ended (conn_state).

Two formats are supported:
    - TSV (Zeek's default): header lines start with '#'. The '#fields' line
      names the columns, then each connection is one tab-separated line.
      '-' means "unset" and '(empty)' means "empty".
    - JSON (Zeek with `LogAscii::use_json=T`): one JSON object per line.
      Unset fields are simply left out.

Both formats become the same ConnRecord, so later milestones never need to
care which format the log was written in.

Safety note: log contents are only parsed as text and numbers. Nothing in a
log is ever executed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from netwatch.pcap_inspect import DEFAULT_LIMIT, MAX_LIMIT, MISSING, positive_limit

# Without these three fields a connection record is useless.
REQUIRED_FIELDS = ["ts", "id.orig_h", "id.resp_h"]

# How many skipped-line messages the CLI prints before summarising.
MAX_ERRORS_SHOWN = 10

# What each Zeek conn_state code means (paraphrased from Zeek's documentation).
# "Originator" = the side that started the connection; "responder" = the other side.
CONN_STATES = {
    "S0": "Attempt seen, no reply",
    "S1": "Established, not closed",
    "SF": "Normal setup and close",
    "REJ": "Attempt rejected",
    "S2": "Established, originator tried to close, no reply",
    "S3": "Established, responder tried to close, no reply",
    "RSTO": "Established, originator reset (RST)",
    "RSTR": "Established, responder reset (RST)",
    "RSTOS0": "Originator sent SYN then RST, no SYN-ACK",
    "RSTRH": "Responder sent SYN-ACK then RST, no SYN seen",
    "SH": "Originator sent SYN then FIN, no SYN-ACK",
    "SHR": "Responder sent SYN-ACK then FIN, no SYN seen",
    "OTH": "No SYN seen (midstream traffic or not TCP)",
}


class ZeekLogError(Exception):
    """The whole file cannot be read as a conn.log (missing, empty, wrong log type...)."""


@dataclass
class ConnRecord:
    """One connection, normalised. A field Zeek did not record is None."""

    ts: datetime                 # connection start time, timezone-aware UTC
    uid: str | None              # Zeek's unique connection ID, links to other logs
    src_ip: str                  # id.orig_h: originator (who started it)
    src_port: int | None         # id.orig_p
    dst_ip: str                  # id.resp_h: responder
    dst_port: int | None         # id.resp_p
    proto: str | None            # transport protocol: "tcp", "udp" or "icmp"
    service: str | None          # application protocol Zeek detected, e.g. "http", "dns"
    duration: float | None       # seconds
    orig_bytes: int | None       # payload bytes sent by the originator
    resp_bytes: int | None       # payload bytes sent by the responder
    orig_pkts: int | None        # packets sent by the originator
    resp_pkts: int | None        # packets sent by the responder
    conn_state: str | None       # e.g. "SF", "S0", "REJ" (see CONN_STATES)
    history: str | None          # TCP flag history, e.g. "ShADadFf"
    icmp_type: int | None = None  # ICMP only (Zeek stores it in id.orig_p)
    icmp_code: int | None = None  # ICMP only (Zeek stores it in id.resp_p)


@dataclass
class ConnLogResult:
    path: Path
    log_format: str                                       # "tsv" or "json"
    records: list[ConnRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)       # e.g. "line 12: field 'id.orig_h': ..."


# ---------------------------------------------------------------------------
# Value converters. Each one raises ValueError with a readable message.
# ---------------------------------------------------------------------------

def to_timestamp(value: Any) -> datetime:
    """Zeek time -> timezone-aware UTC datetime.

    TSV and default JSON use epoch seconds, e.g. 1700000000.123456.
    JSON can also use ISO 8601, e.g. "2023-11-14T22:13:20.123456Z".
    """
    if isinstance(value, bool):
        raise ValueError(f"not a valid timestamp: {value!r}")
    if isinstance(value, (int, float)):
        seconds = float(value)
    else:
        text = str(value).strip()
        try:
            seconds = float(text)
        except ValueError:
            try:
                moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"not a valid timestamp: {value!r}") from None
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            return moment.astimezone(timezone.utc)
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise ValueError(f"timestamp out of range: {value!r}") from None


def to_ip(value: Any) -> str:
    """Validate an IPv4/IPv6 address and return it in standard short form."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValueError(f"not a valid IP address: {value!r}") from None


def to_count(value: Any) -> int:
    """A whole number >= 0 (bytes, packets)."""
    if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
        raise ValueError(f"not a whole number: {value!r}")
    try:
        number = int(value) if isinstance(value, (int, float)) else int(str(value).strip())
    except (ValueError, OverflowError):
        raise ValueError(f"not a whole number: {value!r}") from None
    if number < 0:
        raise ValueError(f"must not be negative: {value!r}")
    return number


def to_port(value: Any) -> int:
    port = to_count(value)
    if port > 65535:
        raise ValueError(f"port out of range 0-65535: {value!r}")
    return port


def to_duration(value: Any) -> float:
    """Seconds as a float >= 0."""
    if isinstance(value, bool):
        raise ValueError(f"not a valid duration: {value!r}")
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"not a valid duration: {value!r}") from None
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError(f"not a valid duration: {value!r}")
    return seconds


def to_text(value: Any) -> str:
    return str(value).strip()


# ---------------------------------------------------------------------------
# Normalisation: raw field values -> ConnRecord
# ---------------------------------------------------------------------------

def normalize(raw: dict[str, Any]) -> ConnRecord:
    """Turn one raw row (Zeek field name -> value) into a ConnRecord.

    A missing value is an absent key, None, or an empty string.
    Raises ValueError naming the field if a value is invalid.
    """
    def is_missing(name: str) -> bool:
        return raw.get(name) is None or raw.get(name) == ""

    for name in REQUIRED_FIELDS:
        if is_missing(name):
            raise ValueError(f"missing required field '{name}'")

    def get(name: str, convert: Callable[[Any], Any]) -> Any:
        if is_missing(name):
            return None
        try:
            return convert(raw[name])
        except ValueError as error:
            raise ValueError(f"field '{name}': {error}") from None

    proto = get("proto", lambda v: to_text(v).lower())
    src_port = get("id.orig_p", to_port)
    dst_port = get("id.resp_p", to_port)

    # ICMP has no ports. Zeek reuses the port columns for the ICMP type and
    # code (e.g. 8/0 = echo request), so move them to their own fields.
    icmp_type = icmp_code = None
    if proto == "icmp":
        icmp_type, icmp_code = src_port, dst_port
        src_port = dst_port = None

    return ConnRecord(
        ts=get("ts", to_timestamp),
        uid=get("uid", to_text),
        src_ip=get("id.orig_h", to_ip),
        src_port=src_port,
        dst_ip=get("id.resp_h", to_ip),
        dst_port=dst_port,
        proto=proto,
        service=get("service", lambda v: to_text(v).lower()),
        duration=get("duration", to_duration),
        orig_bytes=get("orig_bytes", to_count),
        resp_bytes=get("resp_bytes", to_count),
        orig_pkts=get("orig_pkts", to_count),
        resp_pkts=get("resp_pkts", to_count),
        conn_state=get("conn_state", lambda v: to_text(v).upper()),
        history=get("history", to_text),
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


# ---------------------------------------------------------------------------
# Format readers
# ---------------------------------------------------------------------------

def decode_separator(text: str) -> str:
    """Zeek writes the separator escaped, e.g. '\\x09' for a tab."""
    decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text.strip())
    return decoded or "\t"


def read_tsv(lines: list[str], result: ConnLogResult) -> None:
    separator, unset, empty = "\t", "-", "(empty)"
    fields: list[str] | None = None

    for line_no, line in enumerate(lines, start=1):
        line = line.rstrip("\r")
        if not line.strip():
            continue

        if line.startswith("#"):
            if line.startswith("#separator"):
                separator = decode_separator(line[len("#separator"):])
                continue
            key, *values = line[1:].split(separator)
            if key == "fields":
                missing = [name for name in REQUIRED_FIELDS if name not in values]
                if missing:
                    raise ZeekLogError(f"Not a conn.log: the #fields header has no {', '.join(missing)} column(s).")
                fields = values
            elif key == "unset_field" and values:
                unset = values[0]
            elif key == "empty_field" and values:
                empty = values[0]
            elif key == "path" and values and values[0] != "conn":
                raise ZeekLogError(f"This is a Zeek '{values[0]}' log, not a conn log.")
            continue  # #open, #close, #types, #set_separator are not needed

        if fields is None:
            raise ZeekLogError(
                f"Line {line_no} has data before any '#fields' header, "
                "so this does not look like a Zeek TSV log."
            )

        values = line.split(separator)
        if len(values) != len(fields):
            result.errors.append(f"line {line_no}: expected {len(fields)} columns, found {len(values)}")
            continue

        raw = {name: None if value in (unset, empty) else value for name, value in zip(fields, values)}
        try:
            result.records.append(normalize(raw))
        except ValueError as error:
            result.errors.append(f"line {line_no}: {error}")

    if fields is None:
        raise ZeekLogError("No '#fields' header found, so this does not look like a Zeek TSV log.")


def read_json(lines: list[str], result: ConnLogResult) -> None:
    for line_no, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as error:
            result.errors.append(f"line {line_no}: invalid JSON ({error.msg})")
            continue
        if not isinstance(row, dict):
            result.errors.append(f"line {line_no}: expected a JSON object, got {type(row).__name__}")
            continue
        try:
            result.records.append(normalize(row))
        except ValueError as error:
            result.errors.append(f"line {line_no}: {error}")


def detect_format(first_line: str) -> str:
    text = first_line.strip()
    if text.startswith("#"):
        return "tsv"
    if text.startswith("{"):
        return "json"
    raise ZeekLogError(
        "Unrecognised format: expected a Zeek TSV log (starts with '#') "
        "or a Zeek JSON log (one '{...}' object per line)."
    )


def parse_conn_log(raw_path: str | Path) -> ConnLogResult:
    """Read a conn.log file. Bad lines are skipped and listed in result.errors.

    Raises ZeekLogError if the file as a whole cannot be used.
    """
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise ZeekLogError(f"Log file not found: {path}")
    if not path.is_file():
        raise ZeekLogError(f"Not a file: {path}")

    # utf-8-sig drops a byte-order mark if an editor added one.
    # Reading in text mode turns Windows CRLF line endings into plain \n.
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.split("\n")

    first_line = next((line for line in lines if line.strip()), None)
    if first_line is None:
        raise ZeekLogError(f"Log file is empty: {path}")

    result = ConnLogResult(path=path.resolve(), log_format=detect_format(first_line))
    if result.log_format == "tsv":
        read_tsv(lines, result)
    else:
        read_json(lines, result)
    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def show(value: Any, fmt: str = "") -> str:
    return MISSING if value is None else format(value, fmt)


def endpoint(ip: str, port: int | None) -> str:
    """'192.0.2.1:80', '[2001:db8::1]:53', or just the IP when there is no port."""
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def format_table(records: list[ConnRecord]) -> str:
    header = (
        f"{'#':>4}  {'Time (UTC)':<23}  {'Proto':<5}  {'Source':<22}  {'Destination':<22}  "
        f"{'Service':<8}  {'Duration':>9}  {'OrigBytes':>9}  {'RespBytes':>9}  "
        f"{'OrigPkts':>8}  {'RespPkts':>8}  {'State':<6}"
    )
    lines = [header, "-" * len(header)]
    for number, r in enumerate(records, start=1):
        lines.append(
            f"{number:>4}  {r.ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]:<23}  {show(r.proto):<5}  "
            f"{endpoint(r.src_ip, r.src_port):<22}  {endpoint(r.dst_ip, r.dst_port):<22}  "
            f"{show(r.service):<8}  {show(r.duration, '.3f'):>9}  {show(r.orig_bytes):>9}  "
            f"{show(r.resp_bytes):>9}  {show(r.orig_pkts):>8}  {show(r.resp_pkts):>8}  "
            f"{show(r.conn_state):<6}"
        )
    return "\n".join(lines)


def format_state_legend(records: list[ConnRecord]) -> str:
    states = sorted({r.conn_state for r in records if r.conn_state})
    lines = ["Connection states shown above:"]
    for state in states:
        lines.append(f"  {state:<7} {CONN_STATES.get(state, 'Unknown state')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command-line entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m netwatch.zeek_conn",
        description="Parse a Zeek conn.log (TSV or JSON) and preview the connections.",
    )
    parser.add_argument("log", help="path to a Zeek conn.log file")
    parser.add_argument(
        "-l", "--limit",
        type=positive_limit,
        default=DEFAULT_LIMIT,
        help=f"number of connections to show (1-{MAX_LIMIT}, default {DEFAULT_LIMIT})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        result = parse_conn_log(args.log)
    except ZeekLogError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if result.errors:
        print(f"Warning: skipped {len(result.errors)} line(s) that could not be parsed:", file=sys.stderr)
        for message in result.errors[:MAX_ERRORS_SHOWN]:
            print(f"  {message}", file=sys.stderr)
        if len(result.errors) > MAX_ERRORS_SHOWN:
            print(f"  ... and {len(result.errors) - MAX_ERRORS_SHOWN} more", file=sys.stderr)
        print(file=sys.stderr)

    shown = result.records[:args.limit]
    print(f"File:    {result.path}")
    print(f"Format:  Zeek {result.log_format.upper()}")
    print(f"Parsed:  {len(result.records)} connection(s), {len(result.errors)} line(s) skipped")

    if not result.records:
        print("\nNo valid connections found in this log.")
        return 1 if result.errors else 0

    print(f"Showing: {len(shown)} of {len(result.records)}\n")
    print(format_table(shown))
    print()
    print(format_state_legend(shown))
    return 0


if __name__ == "__main__":
    sys.exit(main())
