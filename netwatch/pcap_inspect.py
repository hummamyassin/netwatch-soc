"""Preview the packets in a PCAP / PCAPNG file using TShark.

Usage:
    python -m netwatch.pcap_inspect path/to/capture.pcap [--limit 20]

How it works:
    1. Check that the capture file exists and is not empty.
    2. Find the `tshark` program (installed with Wireshark).
    3. Ask tshark to READ the file and print selected fields as tab-separated text.
    4. Turn each line into a PacketSummary and print a table.

Safety notes:
    - This script only reads a file. It never captures live traffic.
    - Packet contents are treated as plain text and are never executed.
    - tshark is called with an argument list (no shell), so a file name
      containing characters like `;` or `&` cannot inject extra commands.
    - `-n` turns off name resolution, so no DNS lookups are sent while reading.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LIMIT = 20
MAX_LIMIT = 1000
TSHARK_TIMEOUT_SECONDS = 60
MISSING = "-"

# Fields we ask tshark for, in this exact order.
# IPv4 and IPv6 use different field names, and TCP and UDP ports are separate
# fields, so we request both and use whichever one the packet actually has.
TSHARK_FIELDS = [
    "frame.time_epoch",  # seconds since 1970-01-01 (UTC)
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "frame.protocols",  # protocol stack, e.g. "eth:ethertype:ip:udp:dns"
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "frame.len",  # packet length in bytes
]


class InspectError(Exception):
    """A problem we can explain to the user in one clear message."""


@dataclass
class PacketSummary:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: str
    dst_port: str
    length: str


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_capture_path(raw_path: str) -> Path:
    """Return the capture file as an absolute Path, or raise InspectError."""
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise InspectError(f"Capture file not found: {path}")
    if not path.is_file():
        raise InspectError(f"Not a file: {path}")
    if path.stat().st_size == 0:
        raise InspectError(f"Capture file is empty: {path}")
    return path.resolve()


def positive_limit(value: str) -> int:
    """argparse type for --limit: a whole number from 1 to MAX_LIMIT."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a whole number, got {value!r}")
    if not 1 <= number <= MAX_LIMIT:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_LIMIT}, got {number}")
    return number


# ---------------------------------------------------------------------------
# Finding and running tshark
# ---------------------------------------------------------------------------

def find_tshark() -> str | None:
    """Return the path to tshark, or None if it cannot be found."""
    found = shutil.which("tshark")
    if found:
        return found

    # On Windows, Wireshark's installer does not always add itself to PATH,
    # so also check the default install folder.
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        default = Path(program_files) / "Wireshark" / "tshark.exe"
        if default.is_file():
            return str(default)

    return None


def build_tshark_command(tshark: str, capture: Path, limit: int) -> list[str]:
    """Build the tshark argument list. Each item is passed as one argument."""
    command = [
        tshark,
        "-r", str(capture),       # read from this file (no live capture)
        "-c", str(limit),         # stop after this many packets
        "-n",                     # no name resolution (no DNS lookups)
        "-T", "fields",           # output only the fields we choose
        "-E", "separator=/t",     # separate fields with a tab
        "-E", "occurrence=f",     # if a field appears twice, keep the first
    ]
    for field in TSHARK_FIELDS:
        command += ["-e", field]
    return command


def run_tshark(command: list[str]) -> tuple[str, str]:
    """Run tshark and return (stdout, warning). Raise InspectError on failure."""
    try:
        result = subprocess.run(
            command,                   # a list, and shell=False (the default)
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TSHARK_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        raise InspectError(f"Could not start tshark at: {command[0]}")
    except subprocess.TimeoutExpired:
        raise InspectError(f"tshark took longer than {TSHARK_TIMEOUT_SECONDS} seconds and was stopped.")

    stderr = result.stderr.strip()
    if result.returncode != 0:
        if not result.stdout.strip():
            raise InspectError(f"tshark could not read the file:\n  {stderr or 'no details given'}")
        # A truncated or damaged capture can still give us some packets.
        return result.stdout, f"tshark reported a problem, showing partial results:\n  {stderr}"
    return result.stdout, ""


# ---------------------------------------------------------------------------
# Parsing tshark output
# ---------------------------------------------------------------------------

def first_value(*values: str) -> str:
    """Return the first non-empty value, or MISSING if all are empty."""
    for value in values:
        if value:
            return value
    return MISSING


def format_timestamp(epoch: str) -> str:
    """Convert '1700000000.123456' to '2023-11-14 22:13:20.123 UTC'."""
    try:
        moment = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return epoch or MISSING
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def top_protocol(protocols: str) -> str:
    """Return the highest protocol layer, e.g. 'eth:ethertype:ip:udp:dns' -> 'DNS'."""
    layers = [layer for layer in protocols.split(":") if layer]
    return layers[-1].upper() if layers else MISSING


def parse_tshark_line(line: str) -> PacketSummary:
    """Turn one tab-separated tshark line into a PacketSummary.

    Fields that a packet does not have (for example ports on an ICMP or ARP
    packet) come back from tshark as empty strings, and are shown as '-'.
    """
    values = line.rstrip("\r\n").split("\t")
    values += [""] * (len(TSHARK_FIELDS) - len(values))  # pad short lines
    f = dict(zip(TSHARK_FIELDS, values))

    return PacketSummary(
        timestamp=format_timestamp(f["frame.time_epoch"]),
        src_ip=first_value(f["ip.src"], f["ipv6.src"]),
        dst_ip=first_value(f["ip.dst"], f["ipv6.dst"]),
        protocol=top_protocol(f["frame.protocols"]),
        src_port=first_value(f["tcp.srcport"], f["udp.srcport"]),
        dst_port=first_value(f["tcp.dstport"], f["udp.dstport"]),
        length=first_value(f["frame.len"]),
    )


def parse_tshark_output(output: str) -> list[PacketSummary]:
    return [parse_tshark_line(line) for line in output.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_table(packets: list[PacketSummary]) -> str:
    header = (
        f"{'#':>4}  {'Time':<27}  {'Source':<22}  {'Destination':<22}  "
        f"{'Protocol':<10}  {'SrcPort':>7}  {'DstPort':>7}  {'Length':>6}"
    )
    lines = [header, "-" * len(header)]
    for number, p in enumerate(packets, start=1):
        lines.append(
            f"{number:>4}  {p.timestamp:<27}  {p.src_ip:<22}  {p.dst_ip:<22}  "
            f"{p.protocol:<10}  {p.src_port:>7}  {p.dst_port:>7}  {p.length:>6}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command-line entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m netwatch.pcap_inspect",
        description="Preview packets from an existing PCAP/PCAPNG file using tshark.",
    )
    parser.add_argument("capture", help="path to a .pcap or .pcapng file")
    parser.add_argument(
        "-l", "--limit",
        type=positive_limit,
        default=DEFAULT_LIMIT,
        help=f"number of packets to show (1-{MAX_LIMIT}, default {DEFAULT_LIMIT})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        capture = validate_capture_path(args.capture)

        tshark = find_tshark()
        if tshark is None:
            raise InspectError(
                "tshark was not found.\n"
                "  Install Wireshark (it includes TShark) and make sure tshark is on your PATH.\n"
                "  See README.md -> Setup."
            )

        output, warning = run_tshark(build_tshark_command(tshark, capture, args.limit))
    except InspectError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if warning:
        print(f"Warning: {warning}", file=sys.stderr)

    packets = parse_tshark_output(output)
    print(f"File: {capture}")
    print(f"Showing {len(packets)} packet(s) (limit {args.limit})\n")
    if packets:
        print(format_table(packets))
    else:
        print("No packets found in this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
