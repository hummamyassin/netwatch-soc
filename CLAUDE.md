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
4. Deterministic detection rules
5. Streamlit SOC dashboard (Plotly)
6. Alert investigation workflow
7. Optional AI explanations (Gemini)
8. Testing and GitHub polish

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
- Tests: stdlib `unittest`, run with `python -m unittest -v`. Mock tshark;
  real-tool tests must `skipIf` the tool is missing. Test data is synthetic, in
  `tests/fixtures/`, using documentation IP ranges only (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24, 2001:db8::/32).
- Target OS: Windows 11 (also keep Linux/macOS working).

## Docs
Keep `README.md` (capabilities + roadmap) and `docs/LEARNING_LOG.md` updated each milestone.
