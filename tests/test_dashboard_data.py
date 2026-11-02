"""Tests for netwatch.dashboard_data (everything the dashboard shows, without a browser).

Run with:  python -m unittest -v
"""

import unittest
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from pandas.testing import assert_frame_equal

from netwatch import analyzer as an
from netwatch import dashboard_data as dd
from netwatch.detection import Alert, run_detection
from netwatch.zeek_conn import ZeekLogError

ROOT = Path(__file__).resolve().parents[1]
DEMO_TSV = ROOT / "data" / "demo" / "conn_demo.log"
DEMO_JSON = ROOT / "data" / "demo" / "conn_demo.json"
FIXTURE_TSV = ROOT / "tests" / "fixtures" / "zeek" / "conn_tsv.log"


def make_alert(alert_id: str, severity: str = "Low", alert_type: str = "High Connection Rate",
               last_minute: int = 0, dst_ip: str | None = "198.51.100.1", ports=(80,)) -> Alert:
    moment = datetime(2025, 1, 1, 12, last_minute, tzinfo=timezone.utc)
    return Alert(alert_id=alert_id, rule_id="NW-002", alert_type=alert_type, severity=severity,
                 src_ip="192.0.2.1", dst_ip=dst_ip, dst_ports=tuple(ports), protocols=("tcp",),
                 first_seen=moment, last_seen=moment, connection_count=1, destination_count=1 if dst_ip else 3,
                 observed_value=1, threshold=1, window_seconds=60, explanation="test", event_ids=("C1",))


class UploadCheckTests(unittest.TestCase):
    def test_display_name_keeps_only_a_safe_label(self):
        self.assertEqual(dd.display_name(r"C:\Users\someone\conn.log"), "conn.log")
        self.assertEqual(dd.display_name("../../etc/passwd.log"), "passwd.log")
        self.assertEqual(dd.display_name("bad\x1b[31mname.log"), "bad[31mname.log")
        self.assertEqual(dd.display_name(""), "uploaded log")
        self.assertEqual(len(dd.display_name("a" * 500 + ".log")), dd.MAX_NAME_LENGTH)

    def test_allowed_extensions(self):
        for name in ["conn.log", "conn.json", "conn.tsv", "conn.txt", "CONN.LOG"]:
            with self.subTest(name=name):
                dd.check_upload(name, 100)

    def test_rejected_extensions(self):
        for name in ["capture.pcap", "capture.pcapng", "tool.exe", "script.py", "noextension"]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(dd.UploadError, "Unsupported file type"):
                    dd.check_upload(name, 100)

    def test_size_limits(self):
        dd.check_upload("conn.log", dd.MAX_UPLOAD_BYTES)  # exactly the limit is fine
        with self.assertRaisesRegex(dd.UploadError, "limit"):
            dd.check_upload("conn.log", dd.MAX_UPLOAD_BYTES + 1)
        with self.assertRaisesRegex(dd.UploadError, "empty"):
            dd.check_upload("conn.log", 0)

    def test_binary_files_are_refused(self):
        cases = {
            b"\xd4\xc3\xb2\xa1rest": "PCAP", b"\x0a\x0d\x0d\x0arest": "PCAPNG",
            b"\x1f\x8b\x08rest": "gzip", b"PK\x03\x04rest": "ZIP", b"text\x00with nul": "binary",
        }
        for data, word in cases.items():
            with self.subTest(word=word):
                with self.assertRaisesRegex(dd.UploadError, word):
                    dd.decode_log_bytes(data)

    def test_decoding(self):
        self.assertEqual(dd.decode_log_bytes("\ufeff#fields\tts".encode("utf-8")), "#fields\tts")
        self.assertIn("\ufffd", dd.decode_log_bytes(b"#bad \xff byte"))  # replaced, no crash
        with self.assertRaisesRegex(dd.UploadError, "empty"):
            dd.decode_log_bytes(b"")


class LoadDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tsv_bytes = DEMO_TSV.read_bytes()
        cls.tsv = dd.load_dataset(cls.tsv_bytes, "conn_demo.log")

    def test_demo_dataset(self):
        self.assertEqual(self.tsv.log_format, "tsv")
        self.assertEqual(len(self.tsv.connections), 450)
        self.assertEqual((self.tsv.skipped_lines, self.tsv.duplicates_removed), ([], 0))
        self.assertRegex(self.tsv.dataset_id, r"^[0-9a-f]{16}$")

    def test_dataset_id_follows_content(self):
        self.assertEqual(dd.load_dataset(self.tsv_bytes, "renamed.log").dataset_id, self.tsv.dataset_id)
        json_ = dd.load_dataset(DEMO_JSON.read_bytes(), "conn_demo.json")
        self.assertNotEqual(json_.dataset_id, self.tsv.dataset_id)
        assert_frame_equal(json_.connections, self.tsv.connections)  # same connections, other format

    def test_windows_line_endings(self):
        crlf = self.tsv_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        dataset = dd.load_dataset(crlf, "crlf.log")
        self.assertEqual(dataset.skipped_lines, [])
        assert_frame_equal(dataset.connections, self.tsv.connections)

    def test_unusable_content(self):
        with self.assertRaises(ZeekLogError):
            dd.load_dataset(b"hello, this is not a log\n", "notes.txt")
        with self.assertRaises(dd.UploadError):
            dd.load_dataset(b"\x0a\x0d\x0d\x0a....", "capture.log")

    def test_only_bad_lines_gives_empty_dataset(self):
        dataset = dd.load_dataset(b'{"ts": "never"}\n{"broken\n', "bad.json")
        self.assertTrue(dataset.connections.empty)
        self.assertEqual(len(dataset.skipped_lines), 2)

    def test_demo_registry_points_at_bundled_files(self):
        for label in dd.DEMO_DATASETS:
            data, name = dd.read_demo(label)
            self.assertTrue(data)
            self.assertTrue(name.startswith("conn_demo"))


class KpiAndChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connections = an.load_log(DEMO_TSV).connections
        cls.alerts = run_detection(cls.connections)

    def test_kpis_come_from_the_engines(self):
        kpis = dd.overview_kpis(self.connections, self.alerts)
        self.assertEqual(kpis, {
            "Total Connections": 450, "Unique Source IPs": 10, "Unique Destination IPs": 19,
            "Total Alerts": 6, "High Severity Alerts": 2, "Medium Severity Alerts": 1, "Low Severity Alerts": 3,
        })

    def test_kpis_for_empty_data(self):
        kpis = dd.overview_kpis(an.records_to_dataframe([]), [])
        self.assertEqual(set(kpis.values()), {0})

    def test_timeline_uses_naive_utc_times(self):
        timeline, bucket = dd.timeline_chart_data(self.connections)
        self.assertEqual(bucket, "1min")
        self.assertIsNone(timeline["time"].dt.tz)
        self.assertEqual(timeline["time"].iloc[0], pd.Timestamp("2025-03-10 08:00:00"))
        self.assertEqual(timeline["connections"].sum(), 450)

    def test_port_labels(self):
        ports = dd.top_ports_chart_data(self.connections, 3)
        self.assertEqual(ports["service"].tolist(), ["53/udp", "443/tcp", "22/tcp"])

    def test_state_labels(self):
        states = dd.state_chart_data(self.connections)
        self.assertIn("SF - Normal setup and close", states["label"].tolist())

    def test_empty_chart_data(self):
        empty = an.records_to_dataframe([])
        self.assertTrue(dd.top_ports_chart_data(empty).empty)
        self.assertTrue(dd.timeline_chart_data(empty)[0].empty)


class AlertTableTests(unittest.TestCase):
    def setUp(self):
        self.alerts = [
            make_alert("NW-002-aaa", "Low", last_minute=50),
            make_alert("NW-001-bbb", "High", "Possible Port Scan", last_minute=10),
            make_alert("NW-004-ccc", "Medium", "Repeated Failed Connections", last_minute=30, dst_ip=None, ports=()),
            make_alert("NW-001-ddd", "High", "Possible Port Scan", last_minute=40),
        ]

    def test_table_columns_and_order(self):
        table = dd.alerts_table(self.alerts)
        self.assertEqual(list(table.columns), dd.ALERT_TABLE_COLUMNS)
        # Most severe first; within a severity, most recent first.
        self.assertEqual(table["Alert ID"].tolist(), ["NW-001-ddd", "NW-001-bbb", "NW-004-ccc", "NW-002-aaa"])
        self.assertEqual(table["Severity"].tolist()[0], "🔴 High")
        self.assertEqual(set(table["Status"]), {"New"})

    def test_missing_values_are_shown_honestly(self):
        row = dd.alerts_table(self.alerts).set_index("Alert ID").loc["NW-004-ccc"]
        self.assertEqual((row["Destination"], row["Ports"]), ("3 hosts", "-"))

    def test_status_comes_from_the_caller(self):
        statuses = {"NW-001-bbb": "Closed"}
        table = dd.alerts_table(self.alerts, lambda alert_id: statuses.get(alert_id, "New"))
        self.assertEqual(table.set_index("Alert ID").loc["NW-001-bbb", "Status"], "Closed")

    def test_empty_table(self):
        table = dd.alerts_table([])
        self.assertTrue(table.empty)
        self.assertEqual(list(table.columns), dd.ALERT_TABLE_COLUMNS)

    def test_filters(self):
        ids = lambda alerts: sorted(a.alert_id for a in alerts)
        self.assertEqual(len(dd.filter_alerts(self.alerts)), 4)
        self.assertEqual(ids(dd.filter_alerts(self.alerts, severities=["High"])), ["NW-001-bbb", "NW-001-ddd"])
        self.assertEqual(ids(dd.filter_alerts(self.alerts, types=["Repeated Failed Connections"])), ["NW-004-ccc"])
        self.assertEqual(dd.filter_alerts(self.alerts, severities=[]), [])
        status = {"NW-002-aaa": "Investigating"}
        self.assertEqual(ids(dd.filter_alerts(self.alerts, statuses=["Investigating"],
                                              status_of=lambda a: status.get(a, "New"))), ["NW-002-aaa"])

    def test_alert_types(self):
        self.assertEqual(dd.alert_types(self.alerts),
                         ["High Connection Rate", "Possible Port Scan", "Repeated Failed Connections"])


class FormattingTests(unittest.TestCase):
    def test_safe_md_neutralises_links_and_images(self):
        escaped = dd.safe_md("![x](http://example.com/a.png) [click](http://example.com)")
        self.assertNotIn("](", escaped)
        self.assertIn(r"\!\[x\]\(http\:", escaped)

    def test_format_ports(self):
        self.assertEqual(dd.format_ports(()), "-")
        self.assertEqual(dd.format_ports((22,)), "22")
        self.assertEqual(dd.format_ports(tuple(range(1, 11)), limit=3), "1, 2, 3, ... (+7)")

    def test_format_ts(self):
        self.assertEqual(dd.format_ts(pd.Timestamp("2025-03-10 08:00:05", tz="UTC")), "2025-03-10 08:00:05 UTC")
        self.assertEqual(dd.format_ts(None), "-")

    def test_alert_label(self):
        label = dd.alert_label(make_alert("NW-002-aaa", dst_ip=None))
        self.assertIn("NW-002-aaa", label)
        self.assertIn("3 hosts", label)


class AlertDetailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerts = {a.rule_id + a.severity: a for a in run_detection(an.load_log(DEMO_TSV).connections)}

    def test_detail_rows(self):
        rows = dd.alert_detail_rows(self.alerts["NW-001High"])
        fields = dict(zip(rows["Field"], rows["Value"]))
        self.assertEqual(fields["Detection rule"], "NW-001 Possible Port Scan")
        self.assertEqual(fields["First seen"], "2025-03-10 08:20:00 UTC")
        self.assertEqual(fields["Related connections"], "60")
        self.assertEqual(fields["Measured"], "60 (peak within one 60-second window)")
        self.assertTrue(fields["Destination ports"].endswith("(+40)"))

    def test_threshold_text_per_rule(self):
        self.assertEqual(dd.threshold_text(self.alerts["NW-004High"]),
                         "at least 10 failed TCP attempts to one service within 60 s")
        self.assertEqual(dd.threshold_text(self.alerts["NW-003Low"]),
                         "any connection that reached a watchlisted port (no time window)")
        rows = dd.alert_detail_rows(self.alerts["NW-003Low"])
        self.assertIn("connection(s)", dict(zip(rows["Field"], rows["Value"]))["Measured"])

    def test_case_history_table(self):
        from netwatch.investigation import InvestigationStore
        store = InvestigationStore("x")
        store.start_investigation("A1", now=datetime(2025, 3, 10, 9, 0, tzinfo=timezone.utc))
        store.close("A1", "Inconclusive", now=datetime(2025, 3, 10, 9, 5, tzinfo=timezone.utc))
        table = dd.case_history_table(store.case("A1"))
        self.assertEqual(table.values.tolist(), [
            ["Investigation started", "", "2025-03-10 09:00:00 UTC"],
            ["Closed", "Inconclusive", "2025-03-10 09:05:00 UTC"],
        ])


class SupportingEventTests(unittest.TestCase):
    def test_events_behind_an_alert(self):
        connections = an.load_log(DEMO_TSV).connections
        alert = next(a for a in run_detection(connections) if a.rule_id == "NW-004" and a.severity == "High")
        events = dd.supporting_events(connections, alert)
        self.assertEqual(len(events), alert.connection_count)
        self.assertEqual(events["Event ID"].tolist(), list(alert.event_ids))
        self.assertEqual(set(events["State"]), {"REJ"})
        self.assertEqual(events["Time (UTC)"].tolist(), sorted(events["Time (UTC)"]))


if __name__ == "__main__":
    unittest.main()
