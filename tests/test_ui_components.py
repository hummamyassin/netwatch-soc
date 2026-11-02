"""Tests for netwatch.ui_components (HTML snippets used by the dashboard).

Run with:  python -m unittest -v

The key property: every value is escaped, so text from logs or analysts'
notes can never turn into markup, links or scripts.
"""

import unittest
from datetime import datetime, timedelta, timezone

from netwatch import ui_components as ui
from netwatch.detection import Alert
from netwatch.investigation import InvestigationStore

T0 = datetime(2025, 3, 10, 8, 50, tzinfo=timezone.utc)
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)> "quoted" & more'


def make_alert(**changes) -> Alert:
    fields = dict(alert_id="NW-004-830a11442946", rule_id="NW-004", alert_type="Repeated Failed Connections",
                  severity="High", src_ip="203.0.113.99", dst_ip="192.0.2.26", dst_ports=(22,), protocols=("tcp",),
                  first_seen=T0, last_seen=T0 + timedelta(seconds=52), connection_count=36, destination_count=1,
                  observed_value=36, threshold=10, window_seconds=60, explanation="36 failed attempts.",
                  event_ids=("C1",))
    fields.update(changes)
    return Alert(**fields)


class EscapingTests(unittest.TestCase):
    def assert_inert(self, html: str) -> None:
        self.assertNotIn("<script", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;script&gt;", html)

    def test_every_builder_escapes_its_input(self):
        self.assert_inert(ui.badge(HOSTILE))
        self.assert_inert(ui.section_header(HOSTILE, HOSTILE))
        self.assert_inert(ui.panel_title(HOSTILE, HOSTILE))
        self.assert_inert(ui.empty_state(HOSTILE, HOSTILE))
        self.assert_inert(ui.key_value_list([(HOSTILE, HOSTILE)], mono_keys=frozenset({HOSTILE})))
        self.assert_inert(ui.explanation_block(HOSTILE))
        self.assert_inert(ui.alert_header(make_alert(alert_type=HOSTILE), "New"))

    def test_notes_in_the_timeline_are_escaped(self):
        store = InvestigationStore("x")
        store.start_investigation("A", now=T0)
        store.add_note("A", HOSTILE, now=T0 + timedelta(minutes=1))
        html = ui.case_timeline(store.case("A"))
        self.assert_inert(html)
        self.assertIn("&quot;quoted&quot; &amp; more", html)

    def test_unknown_tone_falls_back_to_neutral(self):
        self.assertIn("nw-badge--neutral", ui.badge("x", 'evil" onclick="x'))


class ComponentTests(unittest.TestCase):
    def test_severity_and_status_badges(self):
        self.assertIn("nw-badge--high", ui.severity_badge("High"))
        self.assertIn("nw-badge--investigating", ui.status_badge("Investigating"))
        self.assertIn("nw-badge--neutral", ui.severity_badge("Critical"))

    def test_stepper_marks_progress(self):
        html = ui.status_stepper("Investigating")
        self.assertIn('<li class="is-done">New</li>', html)
        self.assertIn('<li class="is-current">Investigating</li>', html)
        self.assertIn('<li class="">Closed</li>', html)

    def test_timeline_is_newest_first_and_pairs_notes(self):
        store = InvestigationStore("x")
        store.start_investigation("A", now=T0)
        store.add_note("A", "first note", now=T0 + timedelta(minutes=1))
        store.close("A", "Inconclusive", note="closing note", now=T0 + timedelta(minutes=2))
        html = ui.case_timeline(store.case("A"))
        self.assertLess(html.index("Closed"), html.index("Investigation started"))
        self.assertLess(html.index("closing note"), html.index("first note"))
        self.assertIn("Inconclusive", html)
        self.assertEqual(html.count("nw-timeline-note"), 2)

    def test_alert_header_for_many_destinations(self):
        html = ui.alert_header(make_alert(dst_ip=None, destination_count=4), "Closed")
        self.assertIn("4 hosts", html)
        self.assertIn("nw-badge--closed", html)

    def test_glossary_terms_get_tooltips(self):
        self.assertIn('title="Rejected: the target answered', ui.term("REJ"))
        self.assertEqual(ui.term("Unknown thing"), "Unknown thing")
        self.assertIn("<abbr", ui.key_value_list([("Severity", "High")]))
        self.assertIn("<abbr", ui.panel_title("Protocol mix", "TCP vs UDP", note_terms=("TCP", "UDP")))
        self.assertIn("<abbr", ui.section_header("Supporting evidence", hint_key="Supporting evidence"))
        for key in ["REJ", "S0", "TCP", "UDP", "Severity", "Detection threshold", "Supporting evidence"]:
            self.assertIn(key, ui.GLOSSARY)

    def test_explanation_keeps_every_word_in_three_parts(self):
        text = ("203.0.113.99 made 36 failed TCP connection attempts to 192.0.2.26:22 within 60 s (threshold: 10). "
                "36 failed attempts from A to B; connection states: REJ=36 (S0 = no reply, REJ = rejected). "
                "Possible causes include automated attempts. Or a client retrying.")
        html = ui.explanation_block(text)
        for label in ["Trigger", "Observed", "Context"]:
            self.assertIn(f"<span>{label}</span>", html)
        self.assertIn("192.0.2.26:22 within 60 s (threshold: 10).</p>", html)
        self.assertIn("Possible causes include automated attempts. Or a client retrying.", html)

    def test_short_explanation_has_only_a_trigger(self):
        html = ui.explanation_block("One sentence only.")
        self.assertIn("Trigger", html)
        self.assertNotIn("Observed", html)

    def test_state_legend_lists_present_states(self):
        html = ui.state_legend(["REJ", "SF", "S0"])
        self.assertIn("Rejected", html)
        self.assertIn("No reply", html)
        self.assertIn("Normal setup and close", html)
        self.assertEqual(ui.state_legend([]), "")

    def test_marker_legend(self):
        html = ui.marker_legend(["High", "Low"])
        self.assertIn("nw-swatch--high", html)
        self.assertNotIn("nw-swatch--medium", html)

    def test_alert_header_shows_route_service_and_facts(self):
        html = ui.alert_header(make_alert(), "New")
        self.assertIn("22 / tcp", html)
        self.assertIn("NW-004-830a11442946", html)
        self.assertIn("Connections <b>36</b>", html)

    def test_evidence_facts(self):
        html = ui.evidence_facts(make_alert())
        self.assertIn("Connections <b>36</b>", html)
        self.assertIn("Time span <b>52 s</b>", html)
        self.assertIn("2025-03-10 08:50:00 UTC", html)


if __name__ == "__main__":
    unittest.main()
