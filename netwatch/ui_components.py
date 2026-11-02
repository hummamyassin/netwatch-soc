"""Small HTML building blocks for the dashboard (badges, key/value lists, timeline).

Each function returns an HTML string that dashboard.py passes to st.html.
Styling lives in assets/dashboard.css. Every value is escaped with
html.escape, so text from logs or from analysts' notes is always shown as
text and can never become markup, links or scripts.

No Streamlit import here, so these functions are unit-tested directly.
"""

from __future__ import annotations

import re
from html import escape

from netwatch.analyzer import describe_state, format_ts
from netwatch.detection import Alert
from netwatch.investigation import CLOSED, INVESTIGATING, NEW, STATUSES, Case

SEVERITY_TONES = {"High": "high", "Medium": "medium", "Low": "low"}
STATUS_TONES = {NEW: "new", INVESTIGATING: "investigating", CLOSED: "closed"}

# Short explanations shown as hover tooltips on technical terms. One or two
# sentences each: enough to orient a newcomer, not a tutorial.
GLOSSARY = {
    "Severity": "How urgently to review the alert (High, Medium, Low). It reflects how strong the signal is, "
                "not proof of an attack.",
    "Rule threshold": "The value a rule must reach inside its time window before it raises an alert.",
    "Detection threshold": "The value a rule must reach inside its time window before it raises an alert.",
    "Supporting evidence": "The exact connections from the Zeek log that made this rule fire.",
    "TCP": "Transmission Control Protocol: connection-based, starts with a handshake. Used by web, SSH, RDP.",
    "UDP": "User Datagram Protocol: no handshake, send-and-forget. Used by DNS, NTP, mDNS.",
    "REJ": "Rejected: the target answered the connection attempt with a reset, usually because the port is closed.",
    "S0": "No reply: an attempt was seen but nothing came back (host down, filtered by a firewall, or one-way UDP).",
    "State": "Zeek's connection state: how the connection went. SF is normal; S0 and REJ are failed attempts.",
}


def term(label: str, key: str | None = None) -> str:
    """A label with a hover explanation from GLOSSARY (plain text when there is none)."""
    hint = GLOSSARY.get(key or label)
    if not hint:
        return escape(label)
    return f'<abbr class="nw-term" title="{escape(hint)}">{escape(label)}</abbr>'


def badge(text: str, tone: str = "neutral") -> str:
    """A small pill. `tone` picks a colour class defined in dashboard.css."""
    safe_tone = tone if tone in {*SEVERITY_TONES.values(), *STATUS_TONES.values(), "neutral"} else "neutral"
    return f'<span class="nw-badge nw-badge--{safe_tone}">{escape(text)}</span>'


def severity_badge(severity: str) -> str:
    return badge(severity, SEVERITY_TONES.get(severity, "neutral"))


def status_badge(status: str) -> str:
    return badge(status, STATUS_TONES.get(status, "neutral"))


def section_header(title: str, note: str = "", hint_key: str | None = None) -> str:
    note_html = f"<p>{escape(note)}</p>" if note else ""
    title_html = term(title, hint_key) if hint_key else escape(title)
    return f'<div class="nw-section"><h2>{title_html}</h2>{note_html}</div>'


def panel_title(title: str, note: str = "", note_terms: tuple[str, ...] = ()) -> str:
    """Panel heading with an optional muted note. Words in `note_terms` get glossary tooltips."""
    note_html = escape(note)
    for word in note_terms:
        note_html = note_html.replace(escape(word), term(word), 1)
    note_html = f"<span>{note_html}</span>" if note else ""
    return f'<div class="nw-panel-title"><strong>{escape(title)}</strong>{note_html}</div>'


def empty_state(title: str, body: str) -> str:
    return f'<div class="nw-empty"><strong>{escape(title)}</strong><p>{escape(body)}</p></div>'


def key_value_list(rows: list[tuple[str, str]], mono_keys: frozenset[str] = frozenset()) -> str:
    """A two-column definition list. Keys in GLOSSARY get a tooltip; `mono_keys` values use the data font."""
    parts = []
    for key, value in rows:
        value_html = escape(str(value))
        if key in mono_keys:
            value_html = f'<span class="nw-mono">{value_html}</span>'
        parts.append(f"<dt>{term(key)}</dt><dd>{value_html}</dd>")
    return f'<dl class="nw-kv">{"".join(parts)}</dl>'


def alert_header(alert: Alert, status: str) -> str:
    """Summary block of the investigation page: badges, alert type, route, and the key facts."""
    destination = alert.dst_ip or f"{alert.destination_count} hosts"
    ports = ", ".join(map(str, alert.dst_ports[:3])) + (" ..." if len(alert.dst_ports) > 3 else "")
    service = " / ".join(filter(None, [ports, ", ".join(alert.protocols)]))
    service_html = f'<span class="nw-alert-service">{escape(service)}</span>' if service else ""
    return (
        '<div class="nw-alert-head">'
        f'<div class="nw-alert-meta">{severity_badge(alert.severity)}{status_badge(status)}'
        f'{badge(alert.rule_id)}<span class="nw-alert-id">{escape(alert.alert_id)}</span></div>'
        f"<h2>{escape(alert.alert_type)}</h2>"
        f'<div class="nw-alert-route"><b>{escape(alert.src_ip)}</b><span aria-hidden="true">&rarr;</span>'
        f"<b>{escape(destination)}</b>{service_html}</div>"
        f"{evidence_facts(alert)}"
        "</div>"
    )


def _sentences(text: str) -> list[str]:
    return [part for part in re.split(r"(?<=\.)\s+(?=[A-Z0-9])", text.strip()) if part]


def explanation_block(text: str) -> str:
    """The rule's explanation split into what triggered, what was observed, and how to read it.

    The words are the rule's own; only the layout changes.
    """
    sentences = _sentences(text)
    parts = [("Trigger", sentences[:1]), ("Observed", sentences[1:2]), ("Context", sentences[2:])]
    rows = "".join(
        f'<div class="nw-why-row nw-why-row--{label.lower()}"><span>{label}</span><p>{escape(" ".join(chunk))}</p></div>'
        for label, chunk in parts if chunk)
    return f'<div class="nw-why"><span class="nw-why-title">Why this alert was raised</span>{rows}</div>'


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
    """One line of key facts: connection count, time span, first and last seen."""
    seconds = (alert.last_seen - alert.first_seen).total_seconds()
    span_text = f"{seconds:.0f} s" if seconds < 120 else f"{seconds / 60:.1f} min"
    facts = [
        ("Connections", str(alert.connection_count)),
        ("Time span", span_text),
        ("First seen", format_ts(alert.first_seen)),
        ("Last seen", format_ts(alert.last_seen)),
    ]
    return '<div class="nw-facts">' + "".join(
        f"<span>{escape(label)} <b>{escape(value)}</b></span>" for label, value in facts) + "</div>"


def state_legend(states: list[str]) -> str:
    """What the connection-state codes in a table mean, for the codes actually present."""
    items = []
    for state in states:
        hint = GLOSSARY.get(state)
        meaning = hint if hint else describe_state(state)
        items.append(f'<span><b class="nw-mono">{escape(state)}</b> {escape(meaning)}</span>')
    return f'<div class="nw-legend">{"".join(items)}</div>' if items else ""


def marker_legend(severities: list[str]) -> str:
    """Key for the timeline's alert markers, one swatch per severity present."""
    swatches = "".join(
        f'<span><i class="nw-swatch nw-swatch--{SEVERITY_TONES.get(s, "neutral")}"></i>{escape(s)}</span>'
        for s in severities)
    return (f'<div class="nw-legend nw-legend--inline"><span>Dotted lines mark where an alert began. '
            f"Hover the markers for the rule and severity.</span>{swatches}</div>")
