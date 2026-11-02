# CLAUDE.md: NetWatch SOC project rules

## What this is
Beginner-friendly portfolio project (repo: `netwatch-soc`) for a Computer
Engineering graduate targeting Junior SOC / security roles. The owner knows
Python, Git and basic networking and is new to practical security. Teach as you build.

## Architecture
PCAP → Wireshark/TShark & Zeek → structured logs → Python detection engine
(deterministic rules) → alerts → Streamlit dashboard.
Optional later: Gemini API to *explain* existing alerts. Never use it to decide detections.

## Milestones (build ONE at a time, and only with explicit approval)
1. Networking, PCAP, Wireshark ✅ (`netwatch/pcap_inspect.py`)
2. Zeek logs ✅ (`netwatch/zeek_conn.py`: conn.log TSV/JSON → `ConnRecord`)
3. Python log analysis ✅ (`netwatch/analyzer.py`: `ConnRecord`s → typed pandas DataFrame + stats)
4. Deterministic detection rules ✅ (`netwatch/detection.py`: NW-001..NW-004 → `Alert`; docs/DETECTION_RULES.md)
5. Streamlit SOC dashboard ✅ (`dashboard.py` UI + `netwatch/dashboard_data.py` data prep)
6. Alert investigation workflow ✅ (`netwatch/investigation.py` + investigation page)
7. Optional AI explanations (Gemini) ⏳ not started: needs the owner's explicit OK
8. Testing and GitHub polish ✅ (final QA, security review, docs, screenshots)

Do not start the next milestone, or add its features early, without the owner's explicit OK.

## Allowed stack
Python, pandas, Streamlit, Plotly, Wireshark/TShark, Zeek, Git/GitHub, Gemini (phase 7 only).
No databases, Docker, cloud infra, microservices, web frameworks or enterprise features.
Add a package to `requirements.txt` only in the milestone that first uses it.
Packages live in the project virtual environment `.venv` (git-ignored); run tools and
tests with `.venv\Scripts\python`. `pcap_inspect.py` and `zeek_conn.py` stay stdlib-only.

## Safety rules
- Offline analysis of existing capture files only. No live capture, port
  scanning, traffic generation or attack tooling.
- Call external tools with `subprocess.run([...])` argument lists. Never `shell=True`.
- Run TShark with `-n` (no name resolution).
- Never execute content from captures. Treat all packet data as untrusted text.
- Never download captures automatically. Never commit `.pcap`/`.pcapng`, logs or secrets.
- Nothing should require admin/root.
- Don't install system software silently. Document the setup instead.
- No `git commit` / `git push` without the owner's explicit approval.

## Coding conventions
- Readable over clever. Small functions, clear names, type hints where helpful.
- Expected failures raise a clear custom error that is printed as one message, not a traceback.
- Missing packet fields are normal (ICMP has no ports, ARP has no IPs). Show `-`.
- Zeek parsing: whole-file problems raise `ZeekLogError`. Bad lines are skipped and
  recorded in `ConnLogResult.errors` as `"line N: ..."`. Missing values are `None`
  (never `"-"`, `""` or `0`). TSV and JSON must produce identical `ConnRecord`s.
  Text fields are restricted to Zeek's own characters (`TEXT_FIELD_RULES`).
- Analysis (pandas): DataFrame columns have fixed dtypes (`ts` = datetime64[us, UTC],
  counts = `Int64`, text = object). Missing stays `<NA>`/`None`; sums report how many
  rows had a value. Sort with explicit tie-breakers (count desc, then IP/port asc).
  Each row has an `event_id` (Zeek uid, else `row-N`); duplicate uids are dropped once.
  No UI code in analysis modules.
- Detection: rules are pure functions of (connections DataFrame, `DetectionConfig`).
  No randomness, no wall-clock time, no AI. Sort input by (ts, event_id) first.
  Sliding windows are inclusive; overlapping triggering windows merge into one alert.
  Alert IDs = rule + SHA-256 of (src, dst, first/last seen, event_ids): never change the
  scheme silently (a regression test pins it). Never invent missing values (`dst_ip`
  None for many destinations; ports/protocols only from data). Missing or normal
  `conn_state` is never "failed"; only TCP S0/REJ/RSTOS0/SH are. Wording: "possible",
  never "confirmed attack". Keep docs/DETECTION_RULES.md in sync with `RULES`.
- Demo data: `scripts/generate_demo_data.py` (fixed seed) writes `data/demo/` and
  `tests/fixtures/zeek/normal_traffic.log`. Tests pin the demo's 6 expected alerts.
- Dashboard: `dashboard.py` is UI only; put logic and formatting in
  `netwatch/dashboard_data.py` (unit-tested). Never fake numbers: everything comes
  from analyzer/detection. Uploads: extension allow-list, 20 MB limit, binary refused,
  parsed in memory (`parse_conn_text`), never written to disk. Escape any file-derived
  text passed to Markdown (`safe_md`); show raw text with `st.code`/`st.dataframe`.
  Cache parsing/detection with `st.cache_data`. `.streamlit/config.toml` keeps the app
  on localhost with telemetry off. UI tests use `streamlit.testing.v1.AppTest`.
- Investigation: workflow rules live in `netwatch/investigation.py` (no Streamlit).
  Actions: start (New→Investigating), close (Investigating→Closed, disposition required),
  reopen (Closed→Investigating). Validate everything before mutating; failures raise
  `WorkflowError` and change nothing. One `InvestigationStore` per dataset ID in
  `st.session_state["investigations"]`: NOT durable (say so in UI and docs). Notes are
  user text: render only through `ui_components` (html.escape), never as Markdown.
  No automation/integrations.
- Design system: docs/DESIGN.md. Tokens in `assets/dashboard.css` mirror
  `.streamlit/config.toml` and the chart constants in `dashboard.py`. Colour is semantic
  only (severity, status, failed states); one accent. No emoji icons (use Material
  Symbols). HTML snippets live in `netwatch/ui_components.py` and escape every value.
  Motion: 200 ms state-change entrances and press feedback only; honour reduced motion.
- Tests: stdlib `unittest`, run with `python -m unittest -v`. Mock tshark;
  real-tool tests must `skipIf` the tool is missing. Test data is synthetic, in
  `tests/fixtures/`, using documentation IP ranges only (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24, 2001:db8::/32).
- Shared helpers: one timestamp format (`analyzer.format_ts`, "YYYY-MM-DD HH:MM:SS UTC"),
  one skipped-lines warning (`zeek_conn.report_skipped_lines`). CLI output stays ASCII.
- Target OS: Windows 11 (also keep Linux/macOS working). Python 3.11+.

## Docs
- `README.md`: portfolio overview (architecture, features, quick start, limitations, roadmap).
- `docs/USAGE.md` (CLI guide), `docs/ARCHITECTURE.md` (modules, data flow, decisions),
  `docs/DETECTION_RULES.md` (rules, severity, false positives), `docs/LEARNING_LOG.md`
  (glossary + what was learned per milestone). Examples in docs must be real tool output.
- Screenshots in `docs/screenshots/` show synthetic demo data only.
