"""NetWatch SOC dashboard: the Streamlit user interface.

Run from the project folder (with the virtual environment active):
    streamlit run dashboard.py

This file only arranges things on screen. Parsing, analysis and detection
live in the netwatch package (zeek_conn, analyzer, detection, dashboard_data),
so every number shown here is computed by tested code.

Privacy: uploaded logs are parsed in memory on this computer. They are never
saved, executed or sent anywhere. .streamlit/config.toml also binds the app
to localhost and turns off Streamlit's usage statistics.
"""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from netwatch import analyzer as an
from netwatch import dashboard_data as dd
from netwatch import investigation as inv
from netwatch.detection import (
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

st.set_page_config(page_title="NetWatch SOC", page_icon="🛡️", layout="wide")

PAGES = ["Dashboard", "Alert Investigation"]
SEVERITY_BADGE_COLORS = {"High": "red", "Medium": "orange", "Low": "blue"}
STATUS_BADGE_COLORS = {inv.NEW: "gray", inv.INVESTIGATING: "orange", inv.CLOSED: "green"}
ACCENT = "#2dd4bf"
CHART_COLORS = ["#2dd4bf", "#60a5fa", "#a78bfa", "#94a3b8", "#f472b6", "#fbbf24"]

# Plotly Express picks colours when a figure is created, so set the defaults once.
px.defaults.template = "plotly_dark"
px.defaults.color_discrete_sequence = CHART_COLORS
SETTING_KEYS = ["cfg_rules", "cfg_scan_ports", "cfg_scan_window", "cfg_rate_connections", "cfg_rate_window",
                "cfg_watchlist", "cfg_failed_attempts", "cfg_failed_window"]


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
        label = st.selectbox("Demo dataset", list(dd.DEMO_DATASETS), key="demo_choice")
        data, name = dd.read_demo(label)
        return load_dataset(data, name)

    upload = st.file_uploader(
        "Zeek conn.log (TSV or JSON)", type=[ext.lstrip(".") for ext in dd.ALLOWED_EXTENSIONS],
        max_upload_size=dd.MAX_UPLOAD_MB, key="upload",
        help=f"Up to {dd.MAX_UPLOAD_MB} MB. Parsed in memory on this computer; never saved or executed.")
    if upload is None:
        st.info("Upload a Zeek conn.log, or switch to the demo dataset.")
        return None
    try:
        dd.check_upload(upload.name, upload.size)
        return load_dataset(upload.getvalue(), upload.name)
    except (dd.UploadError, ZeekLogError) as error:
        st.error(f"Could not use this file: {dd.safe_md(error)}")
        return None


def detection_settings() -> DetectionConfig:
    defaults = DetectionConfig()
    st.session_state.setdefault("applied_config", defaults)
    with st.expander("Detection settings"):
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
            apply = st.form_submit_button("Apply settings", type="primary", key="apply_settings")
            reset = st.form_submit_button("Reset to defaults", key="reset_settings")

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
            except ValueError as error:
                st.error(f"Settings not applied: {dd.safe_md(error)}")
        if reset:
            for key in SETTING_KEYS:
                st.session_state.pop(key, None)
            st.session_state.applied_config = defaults
            st.rerun()
    st.caption("Changes take effect when you press **Apply settings**.")
    return st.session_state.applied_config


def sidebar() -> tuple[str, dd.Dataset | None, DetectionConfig]:
    with st.sidebar:
        st.title("🛡️ NetWatch SOC")
        st.caption("Network Security Monitor & Incident Dashboard")
        page = st.radio("Navigate", PAGES, key="page")
        st.divider()
        dataset = choose_dataset()
        st.divider()
        config = detection_settings()
        st.divider()
        st.caption("Educational project. Alerts describe possible suspicious behaviour that needs "
                   "review, not confirmed attacks.")
    return page, dataset, config


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

def dataset_banner(dataset: dd.Dataset) -> None:
    connections = dataset.connections
    span = an.time_range(connections)
    period = f"{dd.format_ts(span[0])} → {dd.format_ts(span[1])}" if span else "no connections"
    st.caption(f"**{dd.safe_md(dataset.name)}** · Zeek {dataset.log_format.upper()} · "
               f"{len(connections):,} connections · {period}")
    if dataset.skipped_lines:
        st.warning(f"{len(dataset.skipped_lines)} line(s) could not be parsed and were skipped.")
        with st.expander("Show skipped lines"):
            st.code("\n".join(dataset.skipped_lines[:50]), language=None)
    if dataset.duplicates_removed:
        st.info(f"{dataset.duplicates_removed} repeated connection(s) (same Zeek uid) were counted once.")


def kpi_cards(dataset: dd.Dataset, alerts: list[Alert]) -> None:
    kpis = dd.overview_kpis(dataset.connections, alerts)
    names = list(kpis)
    for columns, row in ((st.columns(3), names[:3]), (st.columns(4), names[3:])):
        for column, name in zip(columns, row):
            column.metric(name, f"{kpis[name]:,}", border=True)


def show_chart(fig, key: str, height: int = 300) -> None:
    fig.update_layout(template="plotly_dark", height=height, margin=dict(l=8, r=8, t=8, b=8),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", colorway=CHART_COLORS,
                      showlegend=False)
    st.plotly_chart(fig, theme=None, key=key, config={"displaylogo": False})


def network_analysis(connections) -> None:
    st.subheader("Network Analysis")
    if connections.empty:
        st.info("There are no valid connections to chart.")
        return

    with st.container(border=True):
        timeline, bucket = dd.timeline_chart_data(connections)
        st.markdown(f"**Connections over time** · UTC, {bucket} buckets")
        fig = px.area(timeline, x="time", y="connections", labels={"time": "Time (UTC)", "connections": "Connections"})
        fig.update_traces(line_color=ACCENT)
        show_chart(fig, "chart_timeline", height=260)

    left, right = st.columns(2)
    with left.container(border=True):
        st.markdown("**Top source IPs**")
        sources = dd.top_sources_chart_data(connections)
        fig = px.bar(sources, x="connections", y="src_ip", orientation="h",
                     labels={"connections": "Connections", "src_ip": "Source IP"})
        fig.update_yaxes(type="category", autorange="reversed")
        show_chart(fig, "chart_sources")
    with right.container(border=True):
        st.markdown("**Top destination ports**")
        ports = dd.top_ports_chart_data(connections)
        if ports.empty:
            st.info("No destination ports recorded (for example ICMP-only traffic).")
        else:
            fig = px.bar(ports, x="service", y="connections", labels={"service": "Port/protocol",
                                                                      "connections": "Connections"})
            fig.update_xaxes(type="category")
            show_chart(fig, "chart_ports")

    left, right = st.columns(2)
    with left.container(border=True):
        st.markdown("**TCP vs UDP distribution**")
        protocols = dd.protocol_chart_data(connections)
        fig = px.pie(protocols, names="proto", values="connections", hole=0.55)
        fig.update_traces(textinfo="label+percent", sort=False)
        show_chart(fig, "chart_protocols")
    with right.container(border=True):
        st.markdown("**Connection states**")
        if not an.has_connection_states(connections):
            st.info("This log has no connection states (Zeek's conn_state field is empty).")
        else:
            states = dd.state_chart_data(connections)
            fig = px.bar(states, x="connections", y="label", orientation="h",
                         labels={"connections": "Connections", "label": "State"})
            fig.update_yaxes(type="category", autorange="reversed")
            show_chart(fig, "chart_states")


def alerts_section(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    st.subheader("Security Alerts")
    if not alerts:
        st.success("No alerts. Nothing in this log reached a detection threshold with the current settings.")
        return

    severity_options = list(reversed(SEVERITIES))
    type_options = [rule.name for rule in RULES.values()]
    left, middle, right = st.columns(3)
    severities = left.multiselect("Severity", severity_options, default=severity_options, key="filter_severity")
    types = middle.multiselect("Alert type", type_options, default=type_options, key="filter_type")
    statuses = right.multiselect("Status", list(inv.STATUSES), default=list(inv.STATUSES), key="filter_status")

    shown = dd.filter_alerts(alerts, severities, types, statuses, store.status)
    counts = store.status_counts([alert.alert_id for alert in alerts])
    st.caption(f"Showing {len(shown)} of {len(alerts)} alerts, most severe and most recent first · "
               f"New {counts[inv.NEW]} · Investigating {counts[inv.INVESTIGATING]} · Closed {counts[inv.CLOSED]}. "
               "Alerts are leads for review, not confirmed attacks.")
    table = dd.alerts_table(shown, store.status)
    event = st.dataframe(
        table, hide_index=True, key="alerts_table", on_select="rerun", selection_mode="single-row",
        column_config={
            "Severity": st.column_config.TextColumn(width="small"),
            "Ports": st.column_config.TextColumn(width="small"),
            "Protocol": st.column_config.TextColumn(width="small"),
            "Connections": st.column_config.NumberColumn(format="%d", width="small"),
            "Alert ID": st.column_config.TextColumn(width="medium"),
        },
    )
    selected_rows = event.selection.rows if event is not None else []
    if selected_rows and selected_rows[0] < len(table):
        alert_id = table.iloc[selected_rows[0]]["Alert ID"]
        st.button(f"🔎 Investigate {alert_id}", type="primary", key="investigate_selected",
                  on_click=open_in_investigation, args=(dataset.dataset_id, alert_id))
    else:
        st.caption("Select a row (the box at its left) to open the alert in **Alert Investigation**.")


def dashboard_page(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    st.title("Security Overview")
    dataset_banner(dataset)
    kpi_cards(dataset, alerts)
    network_analysis(dataset.connections)
    alerts_section(dataset, alerts, store)


# ---------------------------------------------------------------------------
# Alert investigation page
# ---------------------------------------------------------------------------

def run_action(action, message: str) -> None:
    """Run a workflow action; on success remember a message and redraw the page."""
    try:
        action()
    except inv.WorkflowError as error:
        st.error(dd.safe_md(error))
        return
    st.session_state["flash"] = message
    st.rerun()


def alert_details(alert: Alert) -> None:
    st.subheader(alert.alert_type)
    st.badge(f"{alert.severity} severity", color=SEVERITY_BADGE_COLORS.get(alert.severity, "gray"))
    rows = dd.alert_detail_rows(alert)
    st.dataframe(rows, hide_index=True, key="alert_details", height=35 * (len(rows) + 1) + 3,
                 column_config={"Field": st.column_config.TextColumn(width="small")})
    st.markdown("**Why this alert was raised**")
    st.info(dd.safe_md(alert.explanation))
    rule = RULES.get(alert.rule_id)
    if rule:
        with st.expander("About this rule and common false positives"):
            st.markdown(dd.safe_md(rule.description))
            st.markdown("\n".join(f"- {dd.safe_md(reason)}" for reason in rule.false_positives))


def workflow_panel(store: inv.InvestigationStore, alert: Alert) -> None:
    case = store.case(alert.alert_id)
    st.subheader("Investigation")
    st.badge(case.status, color=STATUS_BADGE_COLORS.get(case.status, "gray"))
    if case.disposition:
        st.markdown(f"**Disposition:** {dd.safe_md(case.disposition)}")

    key = alert.alert_id
    if case.status == inv.NEW:
        st.write("Review the details and the supporting events, then start the investigation.")
        if st.button("Start investigation", type="primary", key=f"start_{key}"):
            run_action(lambda: store.start_investigation(key), "Investigation started.")
    elif case.status == inv.INVESTIGATING:
        with st.form(f"note_form_{key}", clear_on_submit=True):
            text = st.text_area("Investigation note", max_chars=inv.MAX_NOTE_LENGTH, key=f"note_{key}",
                                placeholder="What did you check? What did you find?")
            if st.form_submit_button("Add note", key=f"add_note_{key}"):
                run_action(lambda: store.add_note(key, text), "Note added.")
        with st.form(f"close_form_{key}"):
            disposition = st.selectbox("Closure disposition", inv.DISPOSITIONS, index=None,
                                       placeholder="Choose a disposition", key=f"disposition_{key}")
            closing_note = st.text_area("Closing note (optional)", max_chars=inv.MAX_NOTE_LENGTH,
                                        key=f"closing_note_{key}")
            if st.form_submit_button("Close alert", type="primary", key=f"close_{key}"):
                if disposition is None:
                    st.error("Choose a disposition before closing the alert.")
                else:
                    run_action(lambda: store.close(key, disposition, closing_note),
                               f"Alert closed as {disposition}.")
    else:
        if st.button("Reopen alert", key=f"reopen_{key}"):
            run_action(lambda: store.reopen(key), "Alert reopened.")

    if case.notes:
        st.markdown(f"**Notes ({len(case.notes)})**")
        for note in reversed(case.notes):
            with st.container(border=True):
                st.caption(dd.format_ts(note.created_at))
                st.text(note.text)  # plain text: notes are never rendered as Markdown
    if case.history:
        st.markdown("**History**")
        st.dataframe(dd.case_history_table(case), hide_index=True, key=f"history_{key}")


def investigation_page(dataset: dd.Dataset, alerts: list[Alert], store: inv.InvestigationStore) -> None:
    st.title("Alert Investigation")
    st.caption("Statuses and notes are kept only in this browser session: they are lost when you reload "
               "the page or restart the app. Each dataset has its own investigation records.")
    if not alerts:
        st.success("No alerts to investigate for this dataset and these detection settings.")
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
        st.success(message)

    details, workflow = st.columns([3, 2], gap="large")
    with details:
        alert_details(alert)
    with workflow:
        workflow_panel(store, alert)

    st.subheader("Supporting connection events")
    st.caption(f"The {alert.connection_count} connection(s) from the log behind this alert, oldest first. "
               "An empty value (None) means Zeek did not record it.")
    st.dataframe(dd.supporting_events(dataset.connections, alert), hide_index=True, key="supporting_events")

    orphaned = store.orphaned(list(by_id))
    if orphaned:
        st.caption(f"{len(orphaned)} investigation record(s) belong to alerts that the current detection "
                   "settings do not produce. They reappear when the settings match again.")


# ---------------------------------------------------------------------------

def main() -> None:
    page, dataset, config = sidebar()
    if dataset is None:
        st.title("NetWatch SOC")
        st.info("Choose the demo dataset or upload a Zeek conn.log in the sidebar to begin.")
        return
    alerts = detect_alerts(dataset.dataset_id, repr(config), dataset, config)
    store = investigation_store(dataset)
    if page == "Dashboard":
        dashboard_page(dataset, alerts, store)
    else:
        investigation_page(dataset, alerts, store)


main()
