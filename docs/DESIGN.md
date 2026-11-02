# Design system

NetWatch SOC's dashboard aims to feel like a small, trustworthy SOC console:
dark, restrained and data-first. Colour is used for meaning (severity,
status, failure), never for decoration. The look draws on the qualities of
mature operations tools, such as hairline panels, calm type and one accent,
without copying any single product.

Implementation: `.streamlit/config.toml` (Streamlit theme), `assets/dashboard.css`
(tokens and components), `netwatch/ui_components.py` (escaped HTML snippets),
chart styling in `dashboard.py` (`style_figure`, `ranked_bars`, `timeline_chart`).

## Tokens

| Token | Value | Use |
|-------|-------|-----|
| `--nw-bg` | `#0b1018` | Page background |
| `--nw-panel` | `#0f1621` | Panels, metric cards, sidebar |
| `--nw-raised` | `#141c29` | Callouts, notes, inputs |
| `--nw-line` / `--nw-line-strong` | `#1e2836` / `#2b3749` | Hairlines, borders, hover borders |
| `--nw-text` | `#e6ecf4` | Primary text |
| `--nw-muted` / `--nw-faint` | `#9aa8bb` / `#7a889c` | Labels, secondary text, axis ticks |
| `--nw-accent` | `#2dd4bf` | Primary actions, current step, selected filters, chart series |
| `--nw-high` / `--nw-medium` / `--nw-low` | `#f2575c` / `#f2a93b` / `#64a8f8` | Severity only |
| `--nw-ok` | `#3ccf91` | Closed status only |

Amber (`--nw-medium`) also marks **failed TCP states** in charts and evidence
tables, the same signal a Medium alert carries.

- **Radius:** 8 px for panels, cards and tables; 6 px for small controls; full pill for badges and filters.
- **Type:** Streamlit's bundled Source Sans for UI, Source Code Pro for
  data (IPs, alert IDs, ports). Tabular numerals everywhere numbers line up.
  Page title 28 px / 650, section 17 px / 600, labels 13 px muted. Sentence case throughout.
- **Spacing:** sections separated by about 28 px, a title sits closer to
  its content than to the previous section, and panel padding is 14–16 px.

## Components

| Component | Where | Notes |
|-----------|-------|-------|
| Section header | Every page section | Title left, one muted context line right (e.g. "5 of 6 still open") |
| Metric card | KPIs | Severity metrics colour only the number |
| Panel | Charts, details, triage, activity | Bordered container with a title and an optional muted note |
| Badge | Severity, status, rule ID | Tinted background, 1 px tinted border, semantic colour |
| Filter pills | Alert queue | Selected = accent-tinted, unselected = outline |
| Key/value list | Alert details | Hairline rows, data values in mono |
| Status stepper | Triage | New / Investigating / Closed; current step accent-tinted |
| Activity timeline | Triage | Newest first, status changes as filled nodes, notes as inline cards |
| Empty state | No log, no alerts, no matches, no connections | Dashed border, says what happened and what to do next |

Feedback for workflow actions uses **toasts** (transient, out of the way).
Errors stay inline next to the control that caused them.

## Charts

- Transparent backgrounds, hairline grid, muted tick labels, no axis titles
  (the panel title names the measure), no chart toolbar.
- Ranked data uses horizontal bars with the value printed after each bar.
  Bar thickness is the same in every chart, and paired panels share a height.
- The timeline marks where each alert **began** with a dotted line in its
  severity colour, so bursts and alerts can be compared at a glance.

## Motion

Motion only conveys a change of state:

- Panels that appear because the analyst did something (opened an alert,
  recorded an action) fade up 4 px over 200 ms with a strong ease-out.
- Buttons and pills press to `scale(0.97)` over 140 ms.
- Hover changes border and text colour only.
- `prefers-reduced-motion` removes all movement.

There are no page-load sequences, looping animations or decorative effects.

## Safety rules for the UI

- Any text that comes from a file or an analyst goes through
  `ui_components` (escaped with `html.escape`) or is shown as plain text in
  tables. Markdown output uses `dashboard_data.safe_md`.
- No emoji as icons: icons are Material Symbols, which Streamlit bundles.
