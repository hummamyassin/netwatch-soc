"""Headless UI tests for dashboard.py using Streamlit's AppTest (no browser needed).

Run with:  python -m unittest -v

These run the real dashboard script in-process and check that what is shown
matches what the analyzer and detection engine compute.
"""

import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "dashboard.py"
FIXTURES = ROOT / "tests" / "fixtures" / "zeek"
TIMEOUT = 120  # seconds; the first run imports pandas and Plotly


def start_app() -> AppTest:
    at = AppTest.from_file(str(APP), default_timeout=TIMEOUT)
    at.run()
    return at


def metrics(at: AppTest) -> dict[str, str]:
    return {metric.label: metric.value for metric in at.metric}


def alerts_table(at: AppTest):
    """The alerts table on the dashboard page (the dataframe with an 'Alert ID' column)."""
    return next(frame.value for frame in at.main.dataframe if "Alert ID" in frame.value.columns)


def upload(at: AppTest, name: str, content: bytes) -> AppTest:
    at.radio(key="source").set_value("Upload a log").run()
    at.file_uploader(key="upload").upload(name, content)
    at.run()
    return at


class DashboardTests(unittest.TestCase):
    def assert_no_crash(self, at: AppTest) -> None:
        self.assertEqual([e.value for e in at.exception], [])

    def test_demo_dataset_shows_engine_results(self):
        at = start_app()
        self.assert_no_crash(at)
        self.assertEqual(metrics(at), {
            "Total Connections": "450", "Unique Source IPs": "10", "Unique Destination IPs": "19",
            "Total Alerts": "6", "High Severity Alerts": "2", "Medium Severity Alerts": "1",
            "Low Severity Alerts": "3",
        })
        table = alerts_table(at)
        self.assertEqual(len(table), 6)
        self.assertEqual(table["Severity"].tolist()[:2], ["🔴 High", "🔴 High"])

    def test_json_demo_gives_the_same_numbers(self):
        at = start_app()
        tsv_metrics = metrics(at)
        at.selectbox(key="demo_choice").set_value("Demo: Zeek JSON (synthetic)").run()
        self.assert_no_crash(at)
        self.assertEqual(metrics(at), tsv_metrics)

    def test_severity_filter(self):
        at = start_app()
        at.multiselect(key="filter_severity").set_value(["High"]).run()
        self.assertEqual(len(alerts_table(at)), 2)

    def test_detection_settings_apply_and_reset(self):
        at = start_app()
        at.number_input(key="cfg_scan_ports").set_value(80)
        at.button(key="apply_settings").click().run()
        self.assert_no_crash(at)
        self.assertEqual(metrics(at)["Total Alerts"], "5")       # 60-port scan is below 80
        at.button(key="reset_settings").click().run()
        self.assertEqual(metrics(at)["Total Alerts"], "6")

    def test_invalid_settings_are_rejected(self):
        at = start_app()
        at.text_input(key="cfg_watchlist").set_value("23, not-a-port")
        at.button(key="apply_settings").click().run()
        self.assert_no_crash(at)
        self.assertTrue(any("Settings not applied" in e.value for e in at.error))
        self.assertEqual(metrics(at)["Total Alerts"], "6")       # previous settings kept

    def test_upload_valid_log(self):
        at = upload(start_app(), "conn_tsv.log", (FIXTURES / "conn_tsv.log").read_bytes())
        self.assert_no_crash(at)
        self.assertEqual(metrics(at)["Total Connections"], "6")

    def test_upload_normal_traffic_without_alerts(self):
        at = upload(start_app(), "normal.log", (FIXTURES / "normal_traffic.log").read_bytes())
        self.assert_no_crash(at)
        self.assertEqual(metrics(at)["Total Alerts"], "0")
        self.assertTrue(any("No alerts" in s.value for s in at.success))

    def test_upload_pcap_is_refused_cleanly(self):
        at = upload(start_app(), "capture.log", b"\x0a\x0d\x0d\x0a" + b"\x00" * 64)
        self.assert_no_crash(at)
        self.assertTrue(any("PCAPNG" in e.value for e in at.error))
        self.assertEqual(len(at.metric), 0)

    def test_upload_garbage_is_refused_cleanly(self):
        at = upload(start_app(), "notes.txt", b"just some notes, not a Zeek log\n")
        self.assert_no_crash(at)
        self.assertTrue(any("Unrecognised format" in e.value for e in at.error))

    def test_upload_with_bad_lines_warns(self):
        content = (FIXTURES / "conn_json.log").read_bytes() + b'{"ts": "never"}\n'
        at = upload(start_app(), "mixed.json", content)
        self.assert_no_crash(at)
        self.assertEqual(metrics(at)["Total Connections"], "6")
        self.assertTrue(any("could not be parsed" in w.value for w in at.warning))

    def test_log_with_only_bad_lines(self):
        at = upload(start_app(), "bad.json", b'{"ts": "never"}\n{"broken\n')
        self.assert_no_crash(at)
        self.assertEqual(metrics(at)["Total Connections"], "0")
        self.assertTrue(any("2 line(s) could not be parsed" in w.value for w in at.warning))
        self.assertTrue(any("no valid connections" in i.value for i in at.info))
        self.assertTrue(any("No alerts" in s.value for s in at.success))

    def test_investigation_page_without_alerts(self):
        at = upload(start_app(), "normal.log", (FIXTURES / "normal_traffic.log").read_bytes())
        at.radio(key="page").set_value("Alert Investigation").run()
        self.assert_no_crash(at)
        self.assertTrue(any("No alerts to investigate" in s.value for s in at.success))

    def test_investigation_page_opens(self):
        at = start_app()
        at.radio(key="page").set_value("Alert Investigation").run()
        self.assert_no_crash(at)
        self.assertEqual(at.main.title[0].value, "Alert Investigation")


def open_investigation(at: AppTest, alert_id: str) -> AppTest:
    at.radio(key="page").set_value("Alert Investigation").run()
    picker = next(box for box in at.main.selectbox if box.key.startswith("picker_"))
    picker.set_value(alert_id).run()
    return at


SCAN_ALERT = "NW-001-a9bbeb729a3d"      # the demo port scan
RETRY_ALERT = "NW-004-92c2a074b055"     # the demo's harmless 8080 retries


class InvestigationWorkflowTests(unittest.TestCase):
    def assert_no_crash(self, at: AppTest) -> None:
        self.assertEqual([e.value for e in at.exception], [])

    def test_details_and_supporting_events(self):
        at = open_investigation(start_app(), SCAN_ALERT)
        self.assert_no_crash(at)
        details = next(d.value for d in at.main.dataframe if "Field" in d.value.columns)
        fields = dict(zip(details["Field"], details["Value"]))
        self.assertEqual(fields["Alert ID"], SCAN_ALERT)
        self.assertEqual(fields["Detection rule"], "NW-001 Possible Port Scan")
        self.assertEqual((fields["Source"], fields["Destination"]), ("203.0.113.66", "192.0.2.20"))
        self.assertEqual(fields["Rule threshold"], "at least 15 distinct ports on one host within 60 s")
        events = next(d.value for d in at.main.dataframe if "Event ID" in d.value.columns)
        self.assertEqual(len(events), 60)

    def test_full_workflow_and_dashboard_status(self):
        at = open_investigation(start_app(), SCAN_ALERT)
        at.button(key=f"start_{SCAN_ALERT}").click().run()
        self.assertTrue(any("Investigation started" in s.value for s in at.success))
        at.text_area(key=f"note_{SCAN_ALERT}").input("Source is external; 50 ports refused, 2 open (22, 80).")
        at.button(key=f"add_note_{SCAN_ALERT}").click().run()
        self.assertIn("Source is external; 50 ports refused, 2 open (22, 80).", [t.value for t in at.main.text])
        at.selectbox(key=f"disposition_{SCAN_ALERT}").set_value("True Positive")
        at.button(key=f"close_{SCAN_ALERT}").click().run()
        self.assert_no_crash(at)
        self.assertTrue(any("closed as True Positive" in s.value for s in at.success))

        at.radio(key="page").set_value("Dashboard").run()
        table = alerts_table(at).set_index("Alert ID")
        self.assertEqual(table.loc[SCAN_ALERT, "Status"], "Closed")
        self.assertEqual(table.loc[RETRY_ALERT, "Status"], "New")
        at.multiselect(key="filter_status").set_value(["Closed"]).run()
        self.assertEqual(alerts_table(at)["Alert ID"].tolist(), [SCAN_ALERT])

    def test_closing_requires_a_disposition(self):
        at = open_investigation(start_app(), RETRY_ALERT)
        at.button(key=f"start_{RETRY_ALERT}").click().run()
        at.button(key=f"close_{RETRY_ALERT}").click().run()
        self.assert_no_crash(at)
        self.assertTrue(any("Choose a disposition" in e.value for e in at.error))
        self.assertEqual(at.session_state["investigations"][dataset_id(at)].status(RETRY_ALERT), "Investigating")

    def test_empty_note_is_rejected(self):
        at = open_investigation(start_app(), RETRY_ALERT)
        at.button(key=f"start_{RETRY_ALERT}").click().run()
        at.text_area(key=f"note_{RETRY_ALERT}").input("   ")
        at.button(key=f"add_note_{RETRY_ALERT}").click().run()
        self.assertTrue(any("cannot be empty" in e.value for e in at.error))

    def test_state_is_kept_per_dataset(self):
        at = open_investigation(start_app(), SCAN_ALERT)
        at.button(key=f"start_{SCAN_ALERT}").click().run()
        tsv_dataset = dataset_id(at)
        # The JSON demo has the same connections, so the same alert IDs, but it is a different file.
        at.selectbox(key="demo_choice").set_value("Demo: Zeek JSON (synthetic)").run()
        at = open_investigation(at, SCAN_ALERT)
        self.assert_no_crash(at)
        self.assertNotEqual(dataset_id(at), tsv_dataset)
        self.assertTrue(any(b.key == f"start_{SCAN_ALERT}" for b in at.main.button))   # New again here
        at.selectbox(key="demo_choice").set_value("Demo: Zeek TSV (synthetic)").run()
        self.assertEqual(at.session_state["investigations"][tsv_dataset].status(SCAN_ALERT), "Investigating")


def dataset_id(at: AppTest) -> str:
    picker = next(box for box in at.main.selectbox if box.key.startswith("picker_"))
    return picker.key.removeprefix("picker_")


if __name__ == "__main__":
    unittest.main()
