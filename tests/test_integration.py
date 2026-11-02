"""End-to-end tests: synthetic Zeek log -> parser -> analyzer -> detection -> dashboard data -> investigation.

Run with:  python -m unittest -v

Each unit is tested on its own elsewhere; these tests check that the pieces
fit together the way the dashboard and the command-line tools use them.
"""

import contextlib
import io
import unittest
from pathlib import Path

from netwatch import analyzer as an
from netwatch import dashboard_data as dd
from netwatch import detection as det
from netwatch import investigation as inv

ROOT = Path(__file__).resolve().parents[1]
DEMO_TSV = ROOT / "data" / "demo" / "conn_demo.log"
DEMO_JSON = ROOT / "data" / "demo" / "conn_demo.json"


class EndToEndTests(unittest.TestCase):
    def test_demo_log_through_the_whole_pipeline(self):
        data = DEMO_JSON.read_bytes()
        dataset = dd.load_dataset(data, "conn_demo.json")          # parse + DataFrame
        alerts = det.run_detection(dataset.connections)             # detection rules
        kpis = dd.overview_kpis(dataset.connections, alerts)        # dashboard numbers
        self.assertEqual((kpis["Total Connections"], kpis["Total Alerts"]), (450, 6))

        scan = next(a for a in alerts if a.rule_id == "NW-001")
        events = dd.supporting_events(dataset.connections, scan)    # evidence behind the alert
        self.assertEqual(len(events), 60)
        self.assertEqual((set(events["Source"]), set(events["Destination"])), ({"203.0.113.66"}, {"192.0.2.20"}))

        stores: dict[str, inv.InvestigationStore] = {}
        store = inv.store_for(stores, dataset.dataset_id)           # analyst workflow
        store.start_investigation(scan.alert_id)
        store.add_note(scan.alert_id, "External host, 60 ports in 24 s, mostly refused.")
        store.close(scan.alert_id, "True Positive")
        table = dd.alerts_table(alerts, store.status).set_index("Alert ID")
        self.assertEqual(table.loc[scan.alert_id, "Status"], "Closed")
        self.assertEqual(list(table["Status"]).count("New"), 5)

        # Loading the same file again (e.g. after a page reload) gives the same
        # dataset ID and the same alert IDs, so the case attaches to the same alert.
        again = dd.load_dataset(data, "conn_demo (copy).json")
        self.assertEqual(again.dataset_id, dataset.dataset_id)
        self.assertIn(scan.alert_id, [a.alert_id for a in det.run_detection(again.connections)])
        self.assertEqual(inv.store_for(stores, again.dataset_id).status(scan.alert_id), "Closed")

    def test_tsv_and_json_pipelines_agree(self):
        tsv = dd.load_dataset(DEMO_TSV.read_bytes(), "conn_demo.log")
        json_ = dd.load_dataset(DEMO_JSON.read_bytes(), "conn_demo.json")
        tsv_alerts, json_alerts = det.run_detection(tsv.connections), det.run_detection(json_.connections)
        self.assertEqual(tsv_alerts, json_alerts)
        self.assertEqual(dd.overview_kpis(tsv.connections, tsv_alerts), dd.overview_kpis(json_.connections, json_alerts))
        self.assertNotEqual(tsv.dataset_id, json_.dataset_id)  # different files, separate investigations

    def test_command_line_tools_match_the_library(self):
        loaded = an.load_log(DEMO_TSV)
        alerts = det.run_detection(loaded.connections)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(an.main([str(DEMO_TSV)]), 0)
            self.assertEqual(det.main([str(DEMO_TSV)]), 0)
        text = out.getvalue()
        self.assertIn(f"Connections:     {len(loaded.connections)} ", text)
        self.assertIn(f"Source IPs:      {an.unique_source_ips(loaded.connections)} unique", text)
        for alert in alerts:
            self.assertIn(alert.alert_id, text)

    def test_stricter_settings_reduce_alerts_without_touching_others(self):
        connections = an.load_log(DEMO_TSV).connections
        default = {a.alert_id for a in det.run_detection(connections)}
        strict = det.DetectionConfig(failed_min_attempts=40, high_rate_min_connections=200)
        remaining = {a.alert_id for a in det.run_detection(connections, strict)}
        self.assertEqual(len(default - remaining), 3)  # both NW-004 alerts and the NW-002 alert
        self.assertTrue(remaining <= default)          # the other alerts keep their IDs


if __name__ == "__main__":
    unittest.main()
