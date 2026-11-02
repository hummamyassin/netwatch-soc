"""NetWatch SOC dashboard: the Streamlit user interface.

Run from the project folder (with the virtual environment active):
    streamlit run dashboard.py

This file only arranges things on screen. Parsing, analysis and detection
live in the netwatch package (zeek_conn, analyzer, detection, dashboard_data),
so every number shown here is computed by tested code. HTML snippets come
from netwatch/ui_components.py (all values escaped) and the styling from
assets/dashboard.css.

Privacy: uploaded logs are parsed in memory on this computer. They are never
saved, executed or sent anywhere. .streamlit/config.toml also binds the app
to localhost and turns off Streamlit's usage statistics.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from netwatch import analyzer as an
from netwatch import dashboard_data as dd
from netwatch import investigation as inv
from netwatch import ui_components as ui
from netwatch.detection import (
    FAILED_TCP_STATES,
    MAX_THRESHOLD,
    MAX_WINDOW_SECONDS,
    RULES,
    SEVERITIES,
    Alert,
    DetectionConfig,
    parse_port_list,
    run_detection,
)
from netwatch.zeek_conn import ZeekLogError

st.set_page_config(page_title="NetWatch SOC", page_icon=":material/shield:", layout="wide")
st.html(Path(__file__).parent / "assets" / "dashboard.css")

PAGES = ["Dashboard", "Alert Investigation"]
SETTING_KEYS = ["cfg_rules", "cfg_scan_ports", "cfg_scan_window", "cfg_rate_connections", "cfg_rate_window",
                "cfg_watchlist", "cfg_failed_attempts", "cfg_failed_window"]

# Chart palette: the same tokens as assets/dashboard.css.
ACCENT, TEXT, MUTED, FAINT, LINE = "#2dd4bf", "#e6ecf4", "#9aa8bb", "#7a889c", "#1e2836"
SEVERITY_COLORS = {"High": "#f2575c", "Medium": "#f2a93b", "Low": "#64a8f8"}
STATUS_COLORS = {inv.NEW: MUTED, inv.INVESTIGATING: "#f2a93b", inv.CLOSED: "#3ccf91"}
CHART_FONT = '"Source Sans 3", "Source Sans Pro", "Segoe UI", sans-serif'


# ---------------------------------------------------------------------------
# Cached work: re-runs only when the file or the detection settings change
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Parsing Zeek log...", max_entries=8)
def load_dataset(data: bytes, name: str) -> dd.Dataset:
    return dd.load_dataset(data, name)


@st.cache_data(show_spinner="Running detection rules...", max_entries=32)
def detect_alerts(dataset_id: str, config_key: str, _dataset: dd.Dataset, _config: DetectionConfig) -> list[Alert]:
    """Cached per (dataset, settings). Streamlit does not hash arguments starting with '_'."""
    return run_detection(_dataset.connections, _config)


# ---------------------------------------------------------------------------
# Investigation state: one store per dataset, in this browser session only
# ---------------------------------------------------------------------------

def investigation_store(dataset: dd.Dataset) -> inv.InvestigationStore:
    """Session state is NOT durable: it is lost on page reload or app restart."""
    stores = st.session_state.setdefault("investigations", {})
    return inv.store_for(stores, dataset.dataset_id)


def open_in_investigation(dataset_id: str, alert_id: str) -> None:
    """Button callback: show this alert on the investigation page."""
    st.session_state[f"picker_{dataset_id}"] = alert_id
    st.session_state["page"] = "Alert Investigation"


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def choose_dataset() -> dd.Dataset | None:
    st.subheader("Data source")
    source = st.radio("Data source", ["Demo dataset", "Upload a log"], key="source", horizontal=True,
                      label_visibility="collapsed")
    if source == "Demo dataset":
        label = st.selectbox("Demo dataset", list(dd.DEMO_DATASETS), key="demo_choice",
                             label_visibility="collapsed")
        data, name = dd.read_demo(label)
        return load_dataset(data, name)

    upload = st.file_uploader(
        "Zeek conn.log (TSV or JSON)", type=[ext.lstrip(".") for ext in dd.ALLOWED_EXTENSIONS],
        max_upload_size=dd.MAX_UPLOAD_MB, key="upload",
        help=f"Up to {dd.MAX_UPLOAD_MB} MB. Parsed in memory on this computer; never saved or executed.")
    if upload is None:
        st.caption("Drop a Zeek conn.log here, or switch back to the demo dataset.")
        return None
    try:
        dd.check_upload(upload.name, upload.size)
        return load_dataset(upload.getvalue(), upload.name)
    except (dd.UploadError, ZeekLogError) as error:
        st.error(f"Could not use this file. {dd.safe_md(error)}", icon=":material/error:")
        return None


def detection_settings() -> DetectionConfig:
    defaults = DetectionConfig()
    st.session_state.setdefault("applied_config", defaults)
    st.subheader("Detection")
    with st.expander("Rule thresholds", icon=":material/tune:"):
        with st.form("detection_settings", border=False):
            rules = st.multiselect("Enabled rules", list(RULES), default=list(defaults.enabled_rules),
                                   format_func=lambda rule_id: f"{rule_id} {RULES[rule_id].name}", key="cfg_rules")
            st.caption("NW-001 Possible Port Scan")
            left, right = st.columns(2)
            scan_ports = left.number_input("Distinct ports", 1, MAX_THRESHOLD, defaults.port_scan_min_ports,
                                           key="cfg_scan_ports")
            scan_window = right.number_input("Window (s)", 1, MAX_WINDOW_SECONDS, defaults.port_scan_window_seconds,
                                             key="cfg_scan_window")
            st.caption("NW-002 High Connection Rate")
            left, right = st.columns(2)
            rate_connections = left.number_input("Connections", 1, MAX_THRESHOLD, defaults.high_rate_min_connections,
                                                 key="cfg_rate_connections")
            rate_window = right.number_input("Window (s)", 1, MAX_WINDOW_SECONDS, defaults.high_rate_window_seconds,
                                             key="cfg_rate_window")
            st.caption("NW-003 Suspicious Destination Port")
            watchlist = st.text_input("Watchlist ports (comma-separated)",
                                      ", ".join(map(str, defaults.watchlist_ports)), key="cfg_watchlist")
            st.caption("NW-004 Repeated Failed Connections")
            left, right = st.columns(2)
            failed_attempts = left.number_input("Failed attempts", 1, MAX_THRESHOLD, defaults.failed_min_attempts,
                                                key="cfg_failed_attempts")
            failed_window = right.number_input("Window (s)", 1, MAX_WINDOW_SECONDS, defaults.failed_window_seconds,
                                               key="cfg_failed_window")
            left, right = st.columns(2)
            apply = left.form_submit_button("Apply settings", type="primary", key="apply_settings",
                                            width="stretch")
            reset = right.form_submit_button("Reset", key="reset_settings", width="stretch")

        if apply:
            try:
                config = DetectionConfig(
                    port_scan_min_ports=int(scan_ports), port_scan_window_seconds=int(scan_window),
                    high_rate_min_connections=int(rate_connections), high_rate_window_seconds=int(rate_window),
                    watchlist_ports=parse_port_list(watchlist), failed_min_attempts=int(failed_attempts),
                    failed_window_seconds=int(failed_window),
                    enabled_rules=tuple(rule_id for rule_id in RULES if rule_id in rules),
                )
                config.validate()
                st.session_state.applied_config = config
                st.toast("Detection settings applied.", icon=":material/check_circle:")
            except ValueError as error:
                st.error(f"Settings not applied: {dd.safe_md(error)}", icon=":material/error:")
        if reset:
            for key in SETTING_KEYS:
                st.session_state.pop(key, None)
            st.session_state.applied_config = defaults
            st.rerun()
    applied = st.session_state.applied_config
    # Compare values, not objects: after a code reload the stored config is an older class instance.
    changed = "" if repr(applied) == repr(defaults) else " Custom thresholds are active."
    st.caption(f"{len(applied.enabled_rules)} of {len(RULES)} rules enabled.{changed}")
    return applied


def sidebar() -> tuple[str, dd.Dataset | None, DetectionConfig]:
    with st.sidebar:
        with st.container(key="brand"):
            st.markdown(":material/shield: **NetWatch SOC**")
            st.caption("Network security monitor and incident triage")
        page = st.radio("Workspace", PAGES, key="page")
        st.divider()
        dataset = choose_dataset()
        st.divider()
        config = detection_settings()
        st.divider()
        st.caption("Educational project. Alerts describe possible suspicious behaviour that needs review, "
                   "not confirmed attacks.")
    return page, dataset, config


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def style_figure(fig, height: int = 280, show_x_axis: bool = True):
    fig.update_layout(
        template="plotly_dark", height=height, margin=dict(l=4, r=12, t=8, b=4), showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", bargap=0.38,
        font=dict(family=CHART_FONT, size=12, color=MUTED),
        hoverlabel=dict(bgcolor="#141c29", bordercolor="#2b3749", font=dict(family=CHART_FONT, color=TEXT)),
        xaxis_title=None, yaxis_title=None,
    )
    axis = dict(gridcolor=LINE, linecolor=LINE, zeroline=False, tickfont=dict(color=FAINT, size=11))
    fig.update_xaxes(**axis, visible=show_x_axis)
    fig.update_yaxes(**axis)
    return fig


def show_chart(fig, key: str) -> None:
    st.plotly_chart(fig, theme=None, key=key, config={"displaylogo": False, "displayModeBar": False})


def ranked_bars(data: pd.DataFrame, label: str, value: str, text, colors=None, hover: str = "", rows: int = 0):
    """Horizontal bars, largest first, with the value printed after each bar.

    `rows` fixes the chart height so panels side by side line up.
    """
    fig = px.bar(data, x=value, y=label, orientation="h")
    fig.update_traces(marker_color=colors if colors is not None else ACCENT, marker_line_width=0, opacity=0.9,
                      text=text, textposition="outside", textfont=dict(color=MUTED, size=11),
                      cliponaxis=False, hovertemplate=hover or "%{y}: %{x}<extra></extra>")
    fig.update_yaxes(type="category", autorange="reversed", showgrid=False, tickfont=dict(color=MUTED, size=11))
    largest = float(data[value].max()) if len(data) else 1.0
    fig.update_xaxes(range=[0, largest * 1.28])  # room for the value labels
    slots = max(rows, len(data), 1)
    style_figure(fig, height=28 * slots + 20, show_x_axis=False)
    # Same bar thickness in every chart: fewer bars in a taller panel get wider gaps.
    fig.update_layout(bargap=1 - 0.55 * max(len(data), 1) / slots)
    return fig


def timeline_chart(connections: pd.DataFrame, alerts: list[Alert]):
    """Connections per bucket, with a severity-coloured marker where each alert began."""
    timeline, bucket = dd.timeline_chart_data(connections)
    fig = px.area(timeline, x="time", y="connections")
    fig.update_traces(line=dict(color=ACCENT, width=1.6), fillcolor="rgba(45, 212, 191, 0.12)",
                      hovertemplate="%{x|%H:%M} UTC<br>%{y} connections<extra></extra>")
    starts = [pd.Timestamp(alert.first_seen).tz_localize(None) for alert in alerts]
    for alert, start in zip(alerts, starts):
        fig.add_vline(x=start, line_width=1.5, line_dash="dot",
                      line_color=SEVERITY_COLORS.get(alert.severity, MUTED), opacity=0.85)
    if alerts:
        # A small marker at the top of each line carries the hover details. It sits at the alert's
        # real first_seen time; nothing is drawn for the time in between.
        top = float(timeline["connections"].max()) * 1.08
        fig.add_scatter(
            x=starts, y=[top] * len(alerts), mode="markers", showlegend=False, cliponaxis=False,
            marker=dict(symbol="triangle-down", size=10, line_width=0,
                        color=[SEVERITY_COLORS.get(a.severity, MUTED) for a in alerts]),
            customdata=[[a.rule_id, a.alert_type, a.severity, dd.format_ts(a.first_seen), a.connection_count]
                        for a in alerts],
            hovertemplate=("<b>%{customdata[1]}</b><br>%{customdata[0]}, %{customdata[2]} severity<br>"
                           "Began %{customdata[3]}<br>%{customdata[4]} supporting connection(s)<extra></extra>"),
        )
    style_figure(fig, height=230)
    fig.update_xaxes(showgrid=False)
    return fig, bucket


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

def dataset_context(dataset: dd.Dataset) -> None:
    connections = dataset.connections
    span = an.time_range(connections)
    period = f"{dd.format_ts(span[0])} to {dd.format_ts(span[1])}" if span else "no valid connections"
    st.html(f'<p class="nw-context"><b>{ui.escape(dataset.name)}</b>&nbsp;&nbsp;Zeek '
            f'{ui.escape(dataset.log_format.upper())}, {len(connections):,} connections, {ui.escape(period)}</p>')
    if dataset.skipped_lines:
        st.warning(f"{len(dataset.skipped_lines)} line(s) could not be parsed and were skipped. "
                   "Everything else in the log is shown.", icon=":material/warning:")
        with st.expander("Show skipped lines"):
            st.code("\n".join(dataset.skipped_lines[:50]), language=None)
    if dataset.duplicates_removed:
        st.info(f"{dataset.duplicates_removed} repeated connection(s) (same Zeek uid) were counted once.",
                icon=":material/content_copy:")


def kpi_row(names: list[str], kpis: dict[str, int], keys: list[str]) -> None:
    for column, name, key in zip(st.columns(len(names)), names, keys):
        with column.container(key=key):
            st.metric(name, f"{kpis[name]:,}")


def overview(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    kpis = dd.overview_kpis(dataset.connections, alerts)
    open_alerts = sum(store.status(a.alert_id) != inv.CLOSED for a in alerts)
    st.html(ui.section_header("Alerts", f"{open_alerts} of {len(alerts)} still open, by severity",
                              hint_key="Severity"))
    kpi_row(["Total Alerts", "High Severity Alerts", "Medium Severity Alerts", "Low Severity Alerts"], kpis,
            ["kpi_total", "kpi_high", "kpi_medium", "kpi_low"])
    st.html(ui.section_header("Traffic", "Unique connections; repeated Zeek uids count once"))
    kpi_row(["Total Connections", "Unique Source IPs", "Unique Destination IPs"], kpis,
            ["kpi_connections", "kpi_sources", "kpi_destinations"])


def styled_alert_table(table: pd.DataFrame):
    def severity_style(value: str) -> str:
        return f"color: {SEVERITY_COLORS.get(value, TEXT)}; font-weight: 600"

    def status_style(value: str) -> str:
        return f"color: {STATUS_COLORS.get(value, TEXT)}"

    return table.style.map(severity_style, subset=["Severity"]).map(status_style, subset=["Status"])


def alert_queue(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    counts = store.status_counts([alert.alert_id for alert in alerts])
    st.html(ui.section_header(
        "Alert queue",
        f"New {counts[inv.NEW]}, Investigating {counts[inv.INVESTIGATING]}, Closed {counts[inv.CLOSED]}"))
    if not alerts:
        st.html(ui.empty_state(
            "No alerts for this log",
            "Nothing reached a detection threshold with the current settings. Lower a threshold under "
            "Detection in the sidebar to see what is close to triggering."))
        return

    severity_options = list(reversed(SEVERITIES))
    left, middle, right = st.columns([1.1, 1.4, 2], vertical_alignment="bottom")
    severities = left.pills("Severity", severity_options, selection_mode="multi", default=severity_options,
                            key="filter_severity")
    statuses = middle.pills("Status", list(inv.STATUSES), selection_mode="multi", default=list(inv.STATUSES),
                            key="filter_status")
    types = right.multiselect("Alert type", [rule.name for rule in RULES.values()], key="filter_type",
                              placeholder="All alert types")

    shown = dd.filter_alerts(alerts, severities, types or None, statuses, store.status)
    if not shown:
        st.html(ui.empty_state("No alerts match these filters",
                               "Select more severities or statuses, or clear the alert type filter."))
        return

    table = dd.alerts_table(shown, store.status)
    event = st.dataframe(
        styled_alert_table(table), hide_index=True, key="alerts_table", on_select="rerun",
        selection_mode="single-row", height=min(35 * (len(table) + 1) + 18, 440),
        column_config={
            "Severity": st.column_config.TextColumn(width="small"),
            "Ports": st.column_config.TextColumn(width="small"),
            "Protocol": st.column_config.TextColumn(width="small"),
            "Connections": st.column_config.NumberColumn(format="%d", width="small"),
            "Alert ID": st.column_config.TextColumn(width="medium"),
        },
    )
    selected_rows = event.selection.rows if event is not None else []
    hint, action = st.columns([3, 1], vertical_alignment="center")
    if selected_rows and selected_rows[0] < len(table):
        alert_id = table.iloc[selected_rows[0]]["Alert ID"]
        hint.caption(f"Selected {alert_id}. Showing {len(shown)} of {len(alerts)} alerts, most severe first.")
        action.button("Investigate", type="primary", key="investigate_selected", icon=":material/arrow_forward:",
                      width="stretch", on_click=open_in_investigation, args=(dataset.dataset_id, alert_id))
    else:
        hint.caption(f"Showing {len(shown)} of {len(alerts)} alerts, most severe first. Select a row to "
                     "investigate it. Alerts are leads for review, not confirmed attacks.")


def traffic_analysis(connections: pd.DataFrame, alerts: list[Alert]) -> None:
    st.html(ui.section_header("Traffic analysis", "All times UTC"))
    if connections.empty:
        st.html(ui.empty_state("No connections to chart",
                               "Every line of this log was skipped. Check the skipped-lines list above."))
        return

    with st.container(border=True):
        fig, bucket = timeline_chart(connections, alerts)
        st.html(ui.panel_title("Connections over time", f"{bucket} buckets"))
        show_chart(fig, "chart_timeline")
        if alerts:
            present = [s for s in reversed(SEVERITIES) if any(a.severity == s for a in alerts)]
            st.html(ui.marker_legend(present))

    sources = dd.top_sources_chart_data(connections)
    ports = dd.top_ports_chart_data(connections)
    rows = max(len(sources), len(ports))
    left, right = st.columns(2)
    with left.container(border=True):
        st.html(ui.panel_title("Top source IPs", "connections started"))
        show_chart(ranked_bars(sources, "src_ip", "connections", sources["connections"], rows=rows),
                   "chart_sources")
    with right.container(border=True):
        st.html(ui.panel_title("Top destination ports", "per protocol"))
        if ports.empty:
            st.html(ui.empty_state("No destination ports", "This log only has traffic without ports, such as ICMP."))
        else:
            show_chart(ranked_bars(ports, "service", "connections", ports["connections"], rows=rows), "chart_ports")

    protocols = dd.protocol_chart_data(connections)
    states = dd.state_chart_data(connections)
    rows = max(len(protocols), len(states))
    left, right = st.columns(2)
    with left.container(border=True):
        st.html(ui.panel_title("Protocol mix", "TCP vs UDP", note_terms=("TCP", "UDP")))
        text = [f"{c:,} ({p:.1f}%)" for c, p in zip(protocols["connections"], protocols["percent"])]
        show_chart(ranked_bars(protocols, "proto", "connections", text, rows=rows), "chart_protocols")
    with right.container(border=True):
        st.html(ui.panel_title("Connection states", "failed TCP attempts (S0, REJ) in amber",
                               note_terms=("S0", "REJ")))
        if not an.has_connection_states(connections):
            st.html(ui.empty_state("No connection states", "Zeek's conn_state field is empty in this log."))
        else:
            colors = [SEVERITY_COLORS["Medium"] if s in FAILED_TCP_STATES else ACCENT for s in states["conn_state"]]
            fig = ranked_bars(states, "conn_state", "connections", states["connections"], colors,
                              hover="%{y}: %{customdata}<br>%{x} connections<extra></extra>", rows=rows)
            fig.update_traces(customdata=states["description"])
            show_chart(fig, "chart_states")


def dashboard_page(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    st.title("Security overview")
    dataset_context(dataset)
    overview(dataset, alerts, store)
    alert_queue(dataset, alerts, store)
    traffic_analysis(dataset.connections, alerts)


# ---------------------------------------------------------------------------
# Alert investigation page
# ---------------------------------------------------------------------------

def run_action(action, message: str) -> None:
    """Run a workflow action; on success remember a message and redraw the page."""
    try:
        action()
    except inv.WorkflowError as error:
        st.error(dd.safe_md(error), icon=":material/error:")
        return
    st.session_state["flash"] = message
    st.rerun()


def alert_details(alert: Alert) -> None:
    st.html(ui.explanation_block(alert.explanation))
    with st.container(border=True):
        st.html(ui.panel_title("Alert details"))
        rows = list(dd.alert_detail_rows(alert).itertuples(index=False, name=None))
        st.html(ui.key_value_list(rows, mono_keys=frozenset({"Alert ID", "Source", "Destination",
                                                             "Destination ports"})))
        rule = RULES.get(alert.rule_id)
        if rule:
            with st.expander("About this rule and common false positives", icon=":material/info:"):
                st.markdown(dd.safe_md(rule.description))
                st.markdown("\n".join(f"- {dd.safe_md(reason)}" for reason in rule.false_positives))


def workflow_panel(store: inv.InvestigationStore, alert: Alert) -> None:
    case = store.case(alert.alert_id)
    key = alert.alert_id
    with st.container(border=True, key="triage_panel"):
        st.html(ui.panel_title("Triage"))
        st.html(ui.status_stepper(case.status))
        if case.disposition:
            st.html(f'<p class="nw-disposition">Closed as <b>{ui.escape(case.disposition)}</b></p>')

        if case.status == inv.NEW:
            st.caption("Review the details and the supporting evidence, then take ownership of the alert.")
            if st.button("Start investigation", type="primary", key=f"start_{key}", icon=":material/play_arrow:",
                         width="stretch"):
                run_action(lambda: store.start_investigation(key), "Investigation started.")
        elif case.status == inv.INVESTIGATING:
            with st.form(f"note_form_{key}", clear_on_submit=True, border=False):
                text = st.text_area("Investigation note", max_chars=inv.MAX_NOTE_LENGTH, key=f"note_{key}",
                                    placeholder="What did you check? What did you find?", height=96)
                if st.form_submit_button("Add note", key=f"add_note_{key}", icon=":material/edit_note:"):
                    run_action(lambda: store.add_note(key, text), "Note added.")
            st.divider()
            with st.form(f"close_form_{key}", border=False):
                disposition = st.selectbox("Closure disposition", inv.DISPOSITIONS, index=None,
                                           placeholder="Choose a disposition", key=f"disposition_{key}")
                closing_note = st.text_area("Closing note (optional)", max_chars=inv.MAX_NOTE_LENGTH,
                                            key=f"closing_note_{key}", height=72)
                if st.form_submit_button("Close alert", type="primary", key=f"close_{key}",
                                         icon=":material/task_alt:", width="stretch"):
                    if disposition is None:
                        st.error("Choose a disposition before closing the alert.", icon=":material/error:")
                    else:
                        run_action(lambda: store.close(key, disposition, closing_note),
                                   f"Alert closed as {disposition}.")
        else:
            if st.button("Reopen alert", key=f"reopen_{key}", icon=":material/undo:", width="stretch"):
                run_action(lambda: store.reopen(key), "Alert reopened.")

    with st.container(border=True):
        st.html(ui.panel_title("Activity", f"{len(case.notes)} note(s)"))
        if case.history:
            st.html(ui.case_timeline(case))
        else:
            st.caption("No activity yet. Actions and notes appear here with UTC timestamps.")


def evidence_table(events: pd.DataFrame):
    def state_style(value) -> str:
        return f"color: {SEVERITY_COLORS['Medium']}" if value in FAILED_TCP_STATES else ""

    return events.style.map(state_style, subset=["State"]).format(
        {"Duration (s)": "{:.4f}"}, na_rep="None")


EVIDENCE_COLUMNS = {
    # Pixel widths sized for IPv4 and Zeek uids, so the key columns fit a 1280 px laptop screen.
    "Time (UTC)": st.column_config.TextColumn("Time (UTC)", width=88, pinned=True),
    "Source": st.column_config.TextColumn("Source IP", width=135),
    "Destination": st.column_config.TextColumn("Destination IP", width=135),
    "Dst port": st.column_config.NumberColumn("Port", format="%d", width=64,
                                              help="Destination port: the service that was contacted."),
    "Proto": st.column_config.TextColumn("Proto", width=64, help="Transport protocol (tcp, udp, icmp)."),
    "State": st.column_config.TextColumn("State", width=72, help=ui.GLOSSARY["State"]),
    "Event ID": st.column_config.TextColumn("Event ID", width=190,
                                            help="Zeek uid of the connection; search it in other Zeek logs."),
    "Src port": st.column_config.NumberColumn("Src port", format="%d"),
    "Duration (s)": st.column_config.NumberColumn("Duration (s)"),
    "Orig bytes": st.column_config.NumberColumn("Bytes out", format="%d", help="Payload bytes sent by the source."),
    "Resp bytes": st.column_config.NumberColumn("Bytes in", format="%d", help="Payload bytes sent back."),
}


def supporting_evidence(dataset: dd.Dataset, alert: Alert) -> None:
    st.html(ui.section_header("Supporting evidence", f"{alert.connection_count} connection(s) from the log, oldest "
                              "first", hint_key="Supporting evidence"))
    events = dd.supporting_events(dataset.connections, alert)
    compact, date = dd.compact_evidence_times(events)
    if date:
        st.caption(f"All on {date} (UTC). Hover a column header for its meaning.")
    # The key columns fit a laptop screen; every field stays one click away below.
    st.dataframe(evidence_table(compact), hide_index=True, key="supporting_events",
                 column_order=dd.EVIDENCE_PRIMARY, column_config=EVIDENCE_COLUMNS,
                 height=min(35 * (len(compact) + 1) + 3, 400))
    states = list(dict.fromkeys(events["State"].dropna()))
    st.html(ui.state_legend(states))
    with st.expander(f"All fields ({len(events.columns)} columns: ports, service, duration, bytes)",
                     icon=":material/table_view:"):
        st.dataframe(evidence_table(events), hide_index=True, key="supporting_events_all",
                     column_config={k: v for k, v in EVIDENCE_COLUMNS.items() if k != "Time (UTC)"})
        st.caption("None means Zeek did not record that value. Failed TCP states are shown in amber.")


def investigation_page(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    st.title("Alert investigation")
    st.caption("Statuses and notes last for this browser session only (lost on reload or restart), "
               "and are kept separately for each dataset.")
    if not alerts:
        st.html(ui.empty_state("Nothing to investigate",
                               "This dataset produced no alerts with the current detection settings."))
        return

    ordered = dd.sort_alerts(alerts)
    by_id = {alert.alert_id: alert for alert in ordered}
    picker = f"picker_{dataset.dataset_id}"
    if st.session_state.get(picker) not in by_id:
        st.session_state[picker] = ordered[0].alert_id
    alert_id = st.selectbox("Alert", list(by_id), format_func=lambda i: dd.alert_label(by_id[i]), key=picker)
    alert = by_id[alert_id]

    message = st.session_state.pop("flash", None)
    if message:
        st.toast(message, icon=":material/check_circle:")

    st.html(ui.alert_header(alert, store.status(alert.alert_id)))

    # Explanation and details on the left; triage actions start at the top of the right column.
    details, workflow = st.columns([1.55, 1], gap="large")
    with details:
        alert_details(alert)
    with workflow:
        workflow_panel(store, alert)

    supporting_evidence(dataset, alert)

    orphaned = store.orphaned(list(by_id))
    if orphaned:
        st.caption(f"{len(orphaned)} investigation record(s) belong to alerts that the current detection "
                   "settings do not produce. They reappear when the settings match again.")


# ---------------------------------------------------------------------------

def main() -> None:
    page, dataset, config = sidebar()
    if dataset is None:
        st.title("Security overview")
        st.html(ui.empty_state("No log loaded",
                               "Choose the demo dataset or upload a Zeek conn.log in the sidebar. "
                               "Files are parsed on this computer and never stored."))
        return
    alerts = detect_alerts(dataset.dataset_id, repr(config), dataset, config)
    store = investigation_store(dataset)
    if page == "Dashboard":
        dashboard_page(dataset, alerts, store)
    else:
        investigation_page(dataset, alerts, store)


main()
