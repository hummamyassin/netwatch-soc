"""Small HTML building blocks for the dashboard (badges, key/value lists, timeline).

Each function returns an HTML string that dashboard.py passes to st.html.
Styling lives in assets/dashboard.css. Every value is escaped with
html.escape, so text from logs or from analysts' notes is always shown as
text and can never become markup, links or scripts.

No Streamlit import here, so these functions are unit-tested directly.
"""

from __future__ import annotations

from html import escape

from netwatch.analyzer import format_ts
from netwatch.detection import Alert
from netwatch.investigation import CLOSED, INVESTIGATING, NEW, STATUSES, Case

SEVERITY_TONES = {"High": "high", "Medium": "medium", "Low": "low"}
STATUS_TONES = {NEW: "new", INVESTIGATING: "investigating", CLOSED: "closed"}


def badge(text: str, tone: str = "neutral") -> str:
    """A small pill. `tone` picks a colour class defined in dashboard.css."""
    safe_tone = tone if tone in {*SEVERITY_TONES.values(), *STATUS_TONES.values(), "neutral"} else "neutral"
    return f'<span class="nw-badge nw-badge--{safe_tone}">{escape(text)}</span>'


def severity_badge(severity: str) -> str:
    return badge(severity, SEVERITY_TONES.get(severity, "neutral"))


def status_badge(status: str) -> str:
    return badge(status, STATUS_TONES.get(status, "neutral"))


def section_header(title: str, note: str = "") -> str:
    note_html = f"<p>{escape(note)}</p>" if note else ""
    return f'<div class="nw-section"><h2>{escape(title)}</h2>{note_html}</div>'


def panel_title(title: str, note: str = "") -> str:
    note_html = f"<span>{escape(note)}</span>" if note else ""
    return f'<div class="nw-panel-title"><strong>{escape(title)}</strong>{note_html}</div>'


def empty_state(title: str, body: str) -> str:
    return f'<div class="nw-empty"><strong>{escape(title)}</strong><p>{escape(body)}</p></div>'


def key_value_list(rows: list[tuple[str, str]], mono_keys: frozenset[str] = frozenset()) -> str:
    """A two-column definition list; values for keys in `mono_keys` use the data font."""
    parts = []
    for key, value in rows:
        value_html = escape(str(value))
        if key in mono_keys:
            value_html = f'<span class="nw-mono">{value_html}</span>'
        parts.append(f"<dt>{escape(key)}</dt><dd>{value_html}</dd>")
    return f'<dl class="nw-kv">{"".join(parts)}</dl>'


def alert_header(alert: Alert, status: str) -> str:
    """Title block of the investigation page: badges, alert type, route, alert ID."""
    destination = alert.dst_ip or f"{alert.destination_count} hosts"
    return (
        '<div class="nw-alert-head">'
        f'<div class="nw-alert-meta">{severity_badge(alert.severity)}{status_badge(status)}'
        f'{badge(alert.rule_id)}</div>'
        f"<h2>{escape(alert.alert_type)}</h2>"
        f'<div class="nw-alert-route"><b>{escape(alert.src_ip)}</b> to <b>{escape(destination)}</b>'
        f"&nbsp;&nbsp;{escape(alert.alert_id)}</div>"
        "</div>"
    )


def explanation_block(text: str) -> str:
    return f'<div class="nw-why"><span class="nw-why-title">Why this alert was raised</span>{escape(text)}</div>'


def status_stepper(status: str) -> str:
    """New / Investigating / Closed, with the current step highlighted and earlier steps marked done."""
    current = STATUSES.index(status) if status in STATUSES else 0
    items = []
    for index, name in enumerate(STATUSES):
        state = "is-current" if index == current else ("is-done" if index < current else "")
        items.append(f'<li class="{state}">{escape(name)}</li>')
    return f'<ol class="nw-steps" aria-label="Investigation status">{"".join(items)}</ol>'


def case_timeline(case: Case) -> str:
    """The case history as a vertical timeline, newest first, with note text inline.

    History records "Note added" entries in the same order as case.notes, so
    each one is paired with its note.
    """
    notes = iter(case.notes)
    entries = []
    for entry in case.history:
        note_html, css_class = "", "is-status"
        if entry.action == "Note added":
            note = next(notes, None)
            css_class = ""
            if note is not None:
                note_html = f'<div class="nw-timeline-note">{escape(note.text)}</div>'
        detail_html = f'<div class="nw-timeline-detail">{escape(entry.detail)}</div>' if entry.detail else ""
        entries.append(
            f'<li class="{css_class}"><div class="nw-timeline-head"><b>{escape(entry.action)}</b>'
            f"<time>{escape(format_ts(entry.at))}</time></div>{detail_html}{note_html}</li>"
        )
    return f'<ol class="nw-timeline">{"".join(reversed(entries))}</ol>'


def evidence_facts(alert: Alert) -> str:
    """One line of facts above the supporting-events table."""
    span = alert.last_seen - alert.first_seen
    seconds = span.total_seconds()
    span_text = f"{seconds:.0f} s" if seconds < 120 else f"{seconds / 60:.1f} min"
    facts = [
        ("Connections", str(alert.connection_count)),
        ("Time span", span_text),
        ("First seen", format_ts(alert.first_seen)),
        ("Last seen", format_ts(alert.last_seen)),
    ]
    return '<div class="nw-facts">' + "".join(
        f"<span>{escape(label)} <b>{escape(value)}</b></span>" for label, value in facts) + "</div>"
