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
2. Zeek logs
3. Python log analysis (pandas)
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
- Tests: stdlib `unittest`, run with `python -m unittest -v`. Mock tshark;
  real-tool tests must `skipIf` the tool is missing.
- Target OS: Windows 11 (also keep Linux/macOS working).

## Docs
Keep `README.md` (capabilities + roadmap) and `docs/LEARNING_LOG.md` updated each milestone.
