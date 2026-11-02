"""Data preparation for the Streamlit dashboard. No Streamlit code lives here.

dashboard.py (the user interface) calls these functions, so everything the
dashboard shows (KPIs, chart data, the alerts table, upload checks) can be
unit-tested without a browser.

Safety:
    Uploaded files are checked (extension, size, binary content), decoded as
    text and parsed in memory. They are never written to disk or executed,
    and their file names are only used as display labels.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import pandas as pd

from netwatch import analyzer as an
from netwatch.analyzer import format_ts  # one timestamp format everywhere: "YYYY-MM-DD HH:MM:SS UTC"
from netwatch.detection import RULES, SEVERITIES, Alert, severity_counts
from netwatch.investigation import NEW, Case
from netwatch.zeek_conn import parse_conn_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_DATASETS = {
    "Demo: Zeek TSV (synthetic)": PROJECT_ROOT / "data" / "demo" / "conn_demo.log",
    "Demo: Zeek JSON (synthetic)": PROJECT_ROOT / "data" / "demo" / "conn_demo.json",
}

ALLOWED_EXTENSIONS = (".log", ".json", ".tsv", ".txt")
MAX_UPLOAD_MB = 20
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_NAME_LENGTH = 80

# First bytes of file types that are definitely not a Zeek text log.
BINARY_SIGNATURES = {
    b"\xd4\xc3\xb2\xa1": "a PCAP capture", b"\xa1\xb2\xc3\xd4": "a PCAP capture",
    b"\x4d\x3c\xb2\xa1": "a PCAP capture", b"\xa1\xb2\x3c\x4d": "a PCAP capture",
    b"\x0a\x0d\x0d\x0a": "a PCAPNG capture", b"\x1f\x8b": "a gzip-compressed file",
    b"PK\x03\x04": "a ZIP archive",
}

SEVERITY_ICONS = {"High": "🔴", "Medium": "🟠", "Low": "🔵"}
DEFAULT_STATUS = NEW

ALERT_TABLE_COLUMNS = ["Severity", "Status", "Alert type", "Source", "Destination", "Ports", "Protocol",
                       "First seen (UTC)", "Last seen (UTC)", "Connections", "Alert ID"]


class UploadError(ValueError):
    """An uploaded file cannot be used; the message is shown to the user."""


@dataclass
class Dataset:
    dataset_id: str                # SHA-256 of the file content (first 16 hex digits)
    name: str                      # display label only, never used as a path
    log_format: str                # "tsv" or "json"
    connections: pd.DataFrame      # one row per unique connection (see analyzer.py)
    skipped_lines: list[str]       # parser messages for lines that were skipped
    duplicates_removed: int


# ---------------------------------------------------------------------------
# Loading data
# ---------------------------------------------------------------------------

def display_name(name: str) -> str:
    """The last part of a file name, without control characters, shortened if very long."""
    last_part = re.split(r"[\\/]", str(name))[-1]
    printable = "".join(ch for ch in last_part if ch.isprintable()).strip()
    if len(printable) > MAX_NAME_LENGTH:
        printable = printable[:MAX_NAME_LENGTH - 3] + "..."
    return printable or "uploaded log"


def check_upload(name: str, size: int) -> None:
    """Reject files with the wrong extension, no content, or too much content."""
    suffix = Path(display_name(name)).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise UploadError(f"Unsupported file type '{suffix or 'none'}'. "
                          f"Upload a Zeek conn.log ({', '.join(ALLOWED_EXTENSIONS)}).")
    if size <= 0:
        raise UploadError("The file is empty.")
    if size > MAX_UPLOAD_BYTES:
        raise UploadError(f"The file is {size / 1024 / 1024:.1f} MB; the limit is {MAX_UPLOAD_MB} MB.")


def decode_log_bytes(data: bytes) -> str:
    """Turn uploaded bytes into text, refusing binary files such as PCAPs."""
    if not data:
        raise UploadError("The file is empty.")
    for signature, kind in BINARY_SIGNATURES.items():
        if data.startswith(signature):
            hint = " Convert captures with Zeek first (see README)." if "PCAP" in kind else ""
            raise UploadError(f"This looks like {kind}, not a Zeek text log.{hint}")
    if b"\x00" in data[:8192]:
        raise UploadError("This looks like a binary file, not a Zeek text log.")
    return data.decode("utf-8-sig", errors="replace")


def load_dataset(data: bytes, name: str) -> Dataset:
    """Parse a Zeek conn.log held in memory. Raises UploadError or ZeekLogError."""
    label = display_name(name)
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(f"The file is larger than {MAX_UPLOAD_MB} MB.")
    result = parse_conn_text(decode_log_bytes(data), label)
    loaded = an.build_loaded_log(result)
    return Dataset(
        dataset_id=hashlib.sha256(data).hexdigest()[:16],
        name=label,
        log_format=result.log_format,
        connections=loaded.connections,
        skipped_lines=list(result.errors),
        duplicates_removed=loaded.duplicates_removed,
    )


def read_demo(label: str) -> tuple[bytes, str]:
    """Bytes and file name of one of the bundled demo datasets (fixed paths only)."""
    path = DEMO_DATASETS[label]
    return path.read_bytes(), path.name


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$:])")


def safe_md(text: object) -> str:
    """Escape Markdown so text from files (e.g. a file name) is shown literally, never as a link or image."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", str(text))


def format_ports(ports: tuple[int, ...], limit: int = 6) -> str:
    if not ports:
        return "-"
    shown = ", ".join(map(str, ports[:limit]))
    return shown if len(ports) <= limit else f"{shown}, ... (+{len(ports) - limit})"


def destination_label(alert: Alert) -> str:
    return alert.dst_ip or f"{alert.destination_count} hosts"


def alert_label(alert: Alert) -> str:
    """One-line description used in selection lists."""
    return (f"{SEVERITY_ICONS.get(alert.severity, '')} {alert.severity} · {alert.alert_type} · "
            f"{alert.src_ip} → {destination_label(alert)} · {alert.alert_id}")


# ---------------------------------------------------------------------------
# KPIs and chart data
# ---------------------------------------------------------------------------

def overview_kpis(connections: pd.DataFrame, alerts: list[Alert]) -> dict[str, int]:
    counts = severity_counts(alerts)
    return {
        "Total Connections": an.total_connections(connections),
        "Unique Source IPs": an.unique_source_ips(connections),
        "Unique Destination IPs": an.unique_destination_ips(connections),
        "Total Alerts": len(alerts),
        "High Severity Alerts": counts["High"],
        "Medium Severity Alerts": counts["Medium"],
        "Low Severity Alerts": counts["Low"],
    }


def timeline_chart_data(connections: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    """Connections per bucket with naive UTC times (Plotly would otherwise shift
    time-zone-aware values to the viewer's local time)."""
    timeline, bucket = an.connections_over_time(connections)
    return timeline.assign(time=timeline["time"].dt.tz_localize(None)), bucket


def top_sources_chart_data(connections: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    return an.top_source_ips(connections, n)


def top_ports_chart_data(connections: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Top destination ports with a 'service' label such as '443/tcp'."""
    table = an.top_destination_ports(connections, n)
    labels = [f"{int(port)}/{proto}" for port, proto in zip(table["dst_port"], table["proto"])]
    return table.assign(service=pd.Series(labels, index=table.index, dtype="object"))


def protocol_chart_data(connections: pd.DataFrame) -> pd.DataFrame:
    return an.protocol_distribution(connections)


def state_chart_data(connections: pd.DataFrame) -> pd.DataFrame:
    """Connection states with a readable label, e.g. 'S0 - Attempt seen, no reply'."""
    table = an.connection_state_distribution(connections)
    labels = [f"{state} - {text}" for state, text in zip(table["conn_state"], table["description"])]
    return table.assign(label=pd.Series(labels, index=table.index, dtype="object"))


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def _no_status(_alert_id: str) -> str:
    return DEFAULT_STATUS


def alert_types(alerts: list[Alert]) -> list[str]:
    return sorted({alert.alert_type for alert in alerts})


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Most severe first, then most recent, then by ID (stable and deterministic)."""
    rank = {severity: n for n, severity in enumerate(SEVERITIES)}
    by_id = sorted(alerts, key=lambda a: a.alert_id)
    by_time = sorted(by_id, key=lambda a: a.last_seen, reverse=True)
    return sorted(by_time, key=lambda a: rank.get(a.severity, -1), reverse=True)


def filter_alerts(alerts: list[Alert], severities: Iterable[str] | None = None,
                  types: Iterable[str] | None = None, statuses: Iterable[str] | None = None,
                  status_of: Callable[[str], str] = _no_status) -> list[Alert]:
    """Keep alerts matching every given filter. None means "do not filter on this"."""
    severities = None if severities is None else set(severities)
    types = None if types is None else set(types)
    statuses = None if statuses is None else set(statuses)
    return [
        alert for alert in alerts
        if (severities is None or alert.severity in severities)
        and (types is None or alert.alert_type in types)
        and (statuses is None or status_of(alert.alert_id) in statuses)
    ]


def alerts_table(alerts: list[Alert], status_of: Callable[[str], str] = _no_status) -> pd.DataFrame:
    """The alerts as display rows (already formatted), most severe and most recent first."""
    rows = [{
        "Severity": f"{SEVERITY_ICONS.get(a.severity, '')} {a.severity}",
        "Alert type": a.alert_type,
        "Source": a.src_ip,
        "Destination": destination_label(a),
        "Ports": format_ports(a.dst_ports),
        "Protocol": ", ".join(a.protocols) or "-",
        "First seen (UTC)": format_ts(a.first_seen).removesuffix(" UTC"),
        "Last seen (UTC)": format_ts(a.last_seen).removesuffix(" UTC"),
        "Connections": a.connection_count,
        "Status": status_of(a.alert_id),
        "Alert ID": a.alert_id,
    } for a in sort_alerts(alerts)]
    return pd.DataFrame(rows, columns=ALERT_TABLE_COLUMNS)


def threshold_text(alert: Alert) -> str:
    """The rule condition that was applied, in words."""
    window = f"within {alert.window_seconds} s"
    return {
        "NW-001": f"at least {alert.threshold} distinct ports on one host {window}",
        "NW-002": f"at least {alert.threshold} connections from one source {window}",
        "NW-003": "any connection that reached a watchlisted port (no time window)",
        "NW-004": f"at least {alert.threshold} failed TCP attempts to one service {window}",
    }.get(alert.rule_id, f"threshold {alert.threshold}")


def alert_detail_rows(alert: Alert) -> pd.DataFrame:
    """Field/value pairs for the alert details view."""
    measured = (f"{alert.observed_value} (peak within one {alert.window_seconds}-second window)"
                if alert.window_seconds else f"{alert.observed_value} connection(s)")
    rows = [
        ("Alert ID", alert.alert_id),
        ("Detection rule", f"{alert.rule_id} {RULES[alert.rule_id].name}" if alert.rule_id in RULES else alert.rule_id),
        ("Severity", alert.severity),
        ("Source", alert.src_ip),
        ("Destination", alert.dst_ip or f"{alert.destination_count} different hosts"),
        ("Protocol", ", ".join(alert.protocols) or "not recorded"),
        ("Destination ports", format_ports(alert.dst_ports, limit=20)),
        ("First seen", format_ts(alert.first_seen)),
        ("Last seen", format_ts(alert.last_seen)),
        ("Related connections", str(alert.connection_count)),
        ("Rule threshold", threshold_text(alert)),
        ("Measured", measured),
    ]
    return pd.DataFrame(rows, columns=["Field", "Value"])


def case_history_table(case: Case) -> pd.DataFrame:
    """The case history, oldest first (action first, so it stays readable in a narrow panel)."""
    return pd.DataFrame(
        [(entry.action, entry.detail, format_ts(entry.at)) for entry in case.history],
        columns=["Action", "Detail", "Time"],
    )


def supporting_events(connections: pd.DataFrame, alert: Alert) -> pd.DataFrame:
    """The connections behind an alert, in time order, formatted for display."""
    events = connections.loc[connections["event_id"].isin(set(alert.event_ids))].sort_values(
        ["ts", "event_id"], kind="mergesort")
    table = pd.DataFrame({
        "Time (UTC)": [format_ts(ts).removesuffix(" UTC") for ts in events["ts"]],
        "Event ID": events["event_id"].tolist(),
        "Source": events["src_ip"].tolist(),
        "Src port": events["src_port"].tolist(),
        "Destination": events["dst_ip"].tolist(),
        "Dst port": events["dst_port"].tolist(),
        "Proto": events["proto"].tolist(),
        "Service": events["service"].tolist(),
        "State": events["conn_state"].tolist(),
        "Duration (s)": events["duration"].tolist(),
        "Orig bytes": events["orig_bytes"].tolist(),
        "Resp bytes": events["resp_bytes"].tolist(),
    })
    return table.astype({"Src port": "Int64", "Dst port": "Int64", "Duration (s)": "Float64",
                         "Orig bytes": "Int64", "Resp bytes": "Int64"})
