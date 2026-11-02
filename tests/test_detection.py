"""Tests for netwatch.detection (rule-based detection engine).

Run with:  python -m unittest -v

Positive tests check that a rule fires, negative tests that it stays quiet on
normal traffic, boundary tests probe the exact thresholds and window edges,
and regression tests pin behaviour that must not change silently.
"""

import contextlib
import io
import random
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwatch import analyzer as an
from netwatch import detection as det
from netwatch.zeek_conn import ConnRecord

ROOT = Path(__file__).resolve().parents[1]
DEMO_TSV = ROOT / "data" / "demo" / "conn_demo.log"
DEMO_JSON = ROOT / "data" / "demo" / "conn_demo.json"
NORMAL = ROOT / "tests" / "fixtures" / "zeek" / "normal_traffic.log"
BASE = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

_uid_counter = 0


def conn(seconds: float = 0, src: str = "192.0.2.1", dst: str = "198.51.100.1", dport: int | None = 80,
         proto: str | None = "tcp", state: str | None = "SF", uid: str | None = None) -> ConnRecord:
    """A synthetic connection `seconds` after BASE, with a unique uid unless one is given."""
    global _uid_counter
    _uid_counter += 1
    return ConnRecord(
        ts=BASE + timedelta(seconds=seconds), uid=uid or f"C{_uid_counter:017d}", src_ip=src,
        src_port=50000 if dport is not None else None, dst_ip=dst, dst_port=dport, proto=proto, service=None,
        duration=None, orig_bytes=None, resp_bytes=None, orig_pkts=None, resp_pkts=None,
        conn_state=state, history=None,
    )


def detect(records: list[ConnRecord], rules: tuple[str, ...] | None = None, **settings) -> list[det.Alert]:
    config = replace(det.DetectionConfig(), **settings)
    if rules is not None:
        config = replace(config, enabled_rules=rules)
    return det.run_detection(an.records_to_dataframe(records), config)


def scan(n_ports: int, spacing: float = 1.0, start: float = 0, src: str = "203.0.113.66",
         dst: str = "192.0.2.20", proto: str = "tcp", state: str = "REJ", first_port: int = 1000) -> list[ConnRecord]:
    """One connection to each of n_ports different ports, `spacing` seconds apart."""
    return [conn(start + n * spacing, src, dst, first_port + n, proto, state) for n in range(n_ports)]


def repeat(count: int, spacing: float = 1.0, start: float = 0, src: str = "192.0.2.5", dst: str = "198.51.100.9",
           dport: int = 22, proto: str = "tcp", state: str | None = "REJ") -> list[ConnRecord]:
    """`count` connections to the same port, `spacing` seconds apart."""
    return [conn(start + n * spacing, src, dst, dport, proto, state) for n in range(count)]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class ConfigTests(unittest.TestCase):
    def test_defaults_are_valid_and_documented(self):
        config = det.DetectionConfig()
        config.validate()
        self.assertEqual((config.port_scan_min_ports, config.port_scan_window_seconds), (15, 60))
        self.assertEqual((config.high_rate_min_connections, config.high_rate_window_seconds), (100, 60))
        self.assertEqual((config.failed_min_attempts, config.failed_window_seconds), (10, 60))
        self.assertEqual(config.watchlist_ports, (23, 3389, 4444, 5900, 6667, 31337))
        self.assertEqual(config.enabled_rules, ("NW-001", "NW-002", "NW-003", "NW-004"))

    def test_invalid_settings_are_rejected(self):
        bad = [
            {"port_scan_min_ports": 0}, {"port_scan_min_ports": -1}, {"port_scan_min_ports": 1.5},
            {"port_scan_min_ports": True}, {"high_rate_min_connections": det.MAX_THRESHOLD + 1},
            {"failed_window_seconds": 0}, {"high_rate_window_seconds": det.MAX_WINDOW_SECONDS + 1},
            {"escalation_factor": 1}, {"watchlist_ports": (70000,)}, {"watchlist_ports": (-1,)},
            {"watchlist_ports": ("23",)}, {"enabled_rules": ("NW-999",)},
        ]
        for settings in bad:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    replace(det.DetectionConfig(), **settings).validate()

    def test_run_detection_validates_config(self):
        with self.assertRaises(ValueError):
            detect([conn()], port_scan_min_ports=0)

    def test_parse_port_list(self):
        self.assertEqual(det.parse_port_list("23, 3389,4444"), (23, 3389, 4444))
        self.assertEqual(det.parse_port_list("4444; 23, 23 ,"), (23, 4444))
        self.assertEqual(det.parse_port_list(""), ())
        for bad in ["abc", "70000", "-1", "1.5", "22 23"]:
            with self.subTest(text=bad):
                with self.assertRaises(ValueError):
                    det.parse_port_list(bad)


# ---------------------------------------------------------------------------
# Sliding windows
# ---------------------------------------------------------------------------

def times(*offsets: float) -> list[datetime]:
    return [BASE + timedelta(seconds=s) for s in offsets]


class EpisodeTests(unittest.TestCase):
    def test_threshold_reached_and_missed(self):
        self.assertEqual(len(det.find_episodes(times(0, 1, 2), None, 60, 3)), 1)
        self.assertEqual(det.find_episodes(times(0, 1), None, 60, 3), [])

    def test_window_edge_is_inclusive(self):
        self.assertEqual(det.find_episodes(times(0, 30, 60), None, 60, 3), [det.Episode(0, 2, 3)])
        self.assertEqual(det.find_episodes(times(0, 30, 60.000001), None, 60, 3), [])

    def test_overlapping_windows_merge_into_one_episode(self):
        # One event every 10 s for 5 minutes: every 60-s window holds 7 events.
        episodes = det.find_episodes(times(*range(0, 301, 10)), None, 60, 6)
        self.assertEqual(episodes, [det.Episode(0, 30, 7)])

    def test_gap_longer_than_window_starts_new_episode(self):
        episodes = det.find_episodes(times(0, 1, 2, 200, 201, 202), None, 60, 3)
        self.assertEqual(episodes, [det.Episode(0, 2, 3), det.Episode(3, 5, 3)])

    def test_distinct_keys(self):
        self.assertEqual(det.find_episodes(times(0, 1, 2, 3), [80, 80, 80, 80], 60, 2), [])
        self.assertEqual(det.find_episodes(times(0, 1, 2, 3), [80, 80, 81, 82], 60, 3), [det.Episode(0, 3, 3)])

    def test_peak_is_the_best_single_window(self):
        episodes = det.find_episodes(times(0, 1, 2, 3, 4, 50, 100), None, 60, 3)
        # The window ending at 50 s holds 6 events (the peak). The event at 100 s
        # is not included: its own window holds only 50 s and 100 s, below the threshold.
        self.assertEqual(episodes, [det.Episode(0, 5, 6)])

    def test_escalation(self):
        self.assertEqual(det.escalate("Medium", 44, 15, 3), "Medium")
        self.assertEqual(det.escalate("Medium", 45, 15, 3), "High")
        self.assertEqual(det.escalate("Low", 300, 100, 3), "Medium")
        self.assertEqual(det.escalate("High", 999, 1, 3), "High")


# ---------------------------------------------------------------------------
# NW-001 Possible Port Scan
# ---------------------------------------------------------------------------

class PortScanTests(unittest.TestCase):
    RULES = ("NW-001",)

    def test_threshold_number_of_ports_triggers(self):
        alerts = detect(scan(15), self.RULES)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a.rule_id, a.alert_type, a.severity), ("NW-001", "Possible Port Scan", "Medium"))
        self.assertEqual((a.src_ip, a.dst_ip, a.protocols), ("203.0.113.66", "192.0.2.20", ("tcp",)))
        self.assertEqual(a.dst_ports, tuple(range(1000, 1015)))
        self.assertEqual((a.connection_count, a.observed_value, a.threshold, a.window_seconds), (15, 15, 15, 60))
        self.assertEqual((a.first_seen, a.last_seen), (BASE, BASE + timedelta(seconds=14)))
        self.assertIn("15 different TCP ports on 192.0.2.20 within 60 s", a.explanation)
        self.assertIn("threshold: 15 ports within 60 s", a.explanation)

    def test_one_port_fewer_does_not_trigger(self):
        self.assertEqual(detect(scan(14), self.RULES), [])

    def test_same_ports_spread_beyond_the_window_do_not_trigger(self):
        self.assertEqual(detect(scan(15, spacing=5), self.RULES), [])  # spans 70 s

    def test_window_boundary(self):
        # 13 ports at 0..12 s plus two more exactly 60 s after the first: one window holds all 15.
        edge = scan(13) + [conn(60, "203.0.113.66", "192.0.2.20", 2000), conn(60, "203.0.113.66", "192.0.2.20", 2001)]
        self.assertEqual(len(detect(edge, self.RULES)), 1)
        # One microsecond later the first port falls out of the window, leaving 14.
        past = scan(13) + [conn(60.000001, "203.0.113.66", "192.0.2.20", 2000),
                           conn(60.000001, "203.0.113.66", "192.0.2.20", 2001)]
        self.assertEqual(detect(past, self.RULES), [])

    def test_repeating_the_same_port_is_not_a_scan(self):
        self.assertEqual(detect(repeat(50, src="203.0.113.66", dst="192.0.2.20", dport=443, state="SF"),
                                self.RULES), [])

    def test_ports_split_across_two_targets_do_not_trigger(self):
        records = scan(8, dst="192.0.2.20") + scan(8, dst="192.0.2.21", first_port=2000)
        self.assertEqual(detect(records, self.RULES), [])

    def test_udp_scan(self):
        alerts = detect(scan(20, proto="udp", state="S0"), self.RULES)
        self.assertEqual([a.protocols for a in alerts], [("udp",)])

    def test_protocols_are_counted_separately(self):
        records = scan(10, proto="tcp") + scan(10, proto="udp", first_port=2000)
        self.assertEqual(detect(records, self.RULES), [])

    def test_icmp_and_missing_ports_are_ignored(self):
        records = [conn(n, "203.0.113.66", "192.0.2.20", None, "icmp", "OTH") for n in range(30)]
        self.assertEqual(detect(records, self.RULES), [])

    def test_severity_escalates_at_three_times_threshold(self):
        self.assertEqual(detect(scan(44, spacing=0.5), self.RULES)[0].severity, "Medium")
        self.assertEqual(detect(scan(45, spacing=0.5), self.RULES)[0].severity, "High")

    def test_long_scan_gives_one_alert(self):
        alerts = detect(scan(100, spacing=1), self.RULES)  # 100 ports over 99 s
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].connection_count, 100)   # every supporting connection
        self.assertEqual(alerts[0].observed_value, 61)      # most ports inside one 60-s window (0..60 s)

    def test_separate_bursts_give_separate_alerts(self):
        alerts = detect(scan(15) + scan(15, start=600, first_port=3000), self.RULES)
        self.assertEqual(len(alerts), 2)
        self.assertNotEqual(alerts[0].alert_id, alerts[1].alert_id)


# ---------------------------------------------------------------------------
# NW-002 High Connection Rate
# ---------------------------------------------------------------------------

class HighRateTests(unittest.TestCase):
    RULES = ("NW-002",)

    def test_threshold_triggers_low(self):
        alerts = detect(repeat(100, spacing=0.5, dport=53, proto="udp", state="SF"), self.RULES)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a.severity, a.observed_value, a.connection_count), ("Low", 100, 100))
        self.assertEqual((a.dst_ip, a.destination_count, a.dst_ports, a.protocols),
                         ("198.51.100.9", 1, (53,), ("udp",)))

    def test_one_fewer_does_not_trigger(self):
        self.assertEqual(detect(repeat(99, spacing=0.5, state="SF"), self.RULES), [])

    def test_slow_steady_traffic_does_not_trigger(self):
        self.assertEqual(detect(repeat(100, spacing=6, state="SF"), self.RULES), [])  # 10 per minute

    def test_three_times_threshold_is_medium(self):
        self.assertEqual(detect(repeat(300, spacing=0.1, state="SF"), self.RULES)[0].severity, "Medium")

    def test_many_destinations(self):
        records = [conn(n * 0.1, "192.0.2.5", f"198.51.100.{n % 4 + 1}", 443) for n in range(100)]
        a = detect(records, self.RULES)[0]
        self.assertIsNone(a.dst_ip)                     # not fabricated: several destinations
        self.assertEqual(a.destination_count, 4)
        self.assertIn("to 4 destination(s), most often 198.51.100.1 (25 connections)", a.explanation)

    def test_icmp_only_alert_has_no_ports(self):
        records = [conn(n * 0.1, "192.0.2.5", "198.51.100.1", None, "icmp", "OTH") for n in range(100)]
        a = detect(records, self.RULES)[0]
        self.assertEqual((a.dst_ports, a.protocols), ((), ("icmp",)))


# ---------------------------------------------------------------------------
# NW-003 Suspicious Destination Port
# ---------------------------------------------------------------------------

class WatchlistTests(unittest.TestCase):
    RULES = ("NW-003",)

    def test_established_connection_to_watchlisted_port(self):
        alerts = detect([conn(0, "192.0.2.12", "203.0.113.80", 4444, state="SF")], self.RULES)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a.rule_id, a.severity, a.dst_ports, a.threshold, a.window_seconds),
                         ("NW-003", "Low", (4444,), 1, None))
        self.assertIn("contextual observation, not evidence of malicious activity", a.explanation)
        self.assertIn("4444/tcp", a.explanation)

    def test_failed_tcp_attempts_are_not_counted(self):
        for state in sorted(det.FAILED_TCP_STATES):
            with self.subTest(state=state):
                self.assertEqual(detect([conn(0, dport=4444, state=state)], self.RULES), [])

    def test_missing_state_is_not_treated_as_failed(self):
        alerts = detect([conn(0, dport=3389, state=None)], self.RULES)
        self.assertEqual(len(alerts), 1)
        self.assertIn("connection states: not recorded", alerts[0].explanation)

    def test_one_way_udp_is_not_a_failed_tcp_attempt(self):
        alerts = detect([conn(0, dport=5000, proto="udp", state="S0")], self.RULES, watchlist_ports=(5000,))
        self.assertEqual(len(alerts), 1)
        self.assertIn("custom watchlist entry", alerts[0].explanation)

    def test_repeated_connections_are_one_alert(self):
        records = [conn(m * 60, "192.0.2.12", "203.0.113.80", 4444) for m in (0, 5, 10)]
        alerts = detect(records, self.RULES)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].connection_count, 3)
        self.assertEqual(alerts[0].last_seen - alerts[0].first_seen, timedelta(minutes=10))

    def test_different_targets_are_separate_alerts(self):
        records = [conn(0, dst="203.0.113.80", dport=4444), conn(1, dst="203.0.113.81", dport=4444)]
        self.assertEqual(len(detect(records, self.RULES)), 2)

    def test_watchlist_is_configurable(self):
        records = [conn(0, dport=4444), conn(1, dport=8080)]
        alerts = detect(records, self.RULES, watchlist_ports=(8080,))
        self.assertEqual([a.dst_ports for a in alerts], [(8080,)])
        self.assertEqual(detect(records, self.RULES, watchlist_ports=()), [])

    def test_missing_protocol(self):
        a = detect([conn(0, dport=23, proto=None, state="SF")], self.RULES)[0]
        self.assertEqual(a.protocols, ())
        self.assertIn("23 (protocol not recorded)", a.explanation)

    def test_normal_ports_do_not_trigger(self):
        self.assertEqual(detect([conn(0, dport=443), conn(1, dport=53, proto="udp")], self.RULES), [])


# ---------------------------------------------------------------------------
# NW-004 Repeated Failed Connections
# ---------------------------------------------------------------------------

class RepeatedFailureTests(unittest.TestCase):
    RULES = ("NW-004",)

    def test_threshold_failures_trigger_medium(self):
        alerts = detect(repeat(10, state="REJ"), self.RULES)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a.severity, a.observed_value, a.dst_ip, a.dst_ports), ("Medium", 10, "198.51.100.9", (22,)))
        self.assertIn("connection states: REJ=10", a.explanation)

    def test_one_fewer_does_not_trigger(self):
        self.assertEqual(detect(repeat(9, state="REJ"), self.RULES), [])

    def test_normal_and_missing_states_are_not_failures(self):
        for state in ["SF", "S1", "RSTO", "RSTR", "OTH", None]:
            with self.subTest(state=state):
                self.assertEqual(detect(repeat(20, state=state), self.RULES), [])

    def test_udp_is_never_a_failed_attempt(self):
        self.assertEqual(detect(repeat(20, dport=514, proto="udp", state="S0"), self.RULES), [])

    def test_all_failed_states_count(self):
        records = []
        for n, state in enumerate(["S0", "REJ", "RSTOS0", "SH"] * 3):
            records.append(conn(n, "192.0.2.5", "198.51.100.9", 22, "tcp", state))
        alerts = detect(records, self.RULES)
        self.assertEqual(alerts[0].observed_value, 12)
        self.assertIn("REJ=3, RSTOS0=3, S0=3, SH=3", alerts[0].explanation)

    def test_successes_in_between_are_not_supporting_events(self):
        records = repeat(10, spacing=2, state="REJ") + repeat(5, spacing=2, start=1, state="SF")
        a = detect(records, self.RULES)[0]
        self.assertEqual(a.connection_count, 10)
        self.assertNotIn("SF", a.explanation)

    def test_failures_to_different_ports_do_not_combine(self):
        records = [conn(n, "192.0.2.5", "198.51.100.9", 1000 + n, state="REJ") for n in range(12)]
        self.assertEqual(detect(records, self.RULES), [])

    def test_three_times_threshold_is_high(self):
        self.assertEqual(detect(repeat(30, spacing=1.5, state="S0"), self.RULES)[0].severity, "High")


# ---------------------------------------------------------------------------
# Whole engine
# ---------------------------------------------------------------------------

class EngineTests(unittest.TestCase):
    def mixed(self) -> list[ConnRecord]:
        return scan(20) + repeat(12, start=100, state="REJ") + [conn(200, dport=4444, state="SF")]

    def test_empty_dataset(self):
        self.assertEqual(det.run_detection(an.records_to_dataframe([])), [])

    def test_missing_columns_are_reported(self):
        frame = an.records_to_dataframe([conn()]).drop(columns=["conn_state"])
        with self.assertRaisesRegex(ValueError, "conn_state"):
            det.run_detection(frame)

    def test_results_are_deterministic(self):
        records = self.mixed()
        first, second = detect(records), detect(records)
        self.assertEqual(first, second)
        for alert in first:
            self.assertRegex(alert.alert_id, r"^NW-00[1-4]-[0-9a-f]{12}$")

    def test_unsorted_input_gives_identical_alerts(self):
        records = self.mixed()
        shuffled = records[:]
        random.Random(7).shuffle(shuffled)
        self.assertEqual(detect(records), detect(shuffled))

    def test_duplicate_events_are_counted_once(self):
        records = scan(15)
        duplicated = records + records[:5]  # same uids again, e.g. a log appended to itself
        self.assertEqual(detect(duplicated), detect(records))
        self.assertEqual(detect(duplicated)[0].connection_count, 15)

    def test_alerts_are_sorted_by_first_seen(self):
        alerts = detect(self.mixed())
        self.assertEqual([a.first_seen for a in alerts], sorted(a.first_seen for a in alerts))

    def test_enabled_rules(self):
        self.assertEqual({a.rule_id for a in detect(self.mixed())}, {"NW-001", "NW-003", "NW-004"})
        self.assertEqual({a.rule_id for a in detect(self.mixed(), ("NW-003",))}, {"NW-003"})
        self.assertEqual(detect(self.mixed(), ()), [])

    def test_changing_config_changes_results_not_ids_of_unaffected_alerts(self):
        records = self.mixed()
        default = {a.rule_id: a.alert_id for a in detect(records)}
        stricter = {a.rule_id: a.alert_id for a in detect(records, port_scan_min_ports=30)}
        self.assertNotIn("NW-001", stricter)
        self.assertEqual(stricter["NW-003"], default["NW-003"])

    def test_severity_counts(self):
        counts = det.severity_counts(detect(self.mixed()))
        self.assertEqual(list(counts), ["High", "Medium", "Low"])
        self.assertEqual(counts, {"High": 0, "Medium": 2, "Low": 1})

    def test_alert_id_regression(self):
        # Pins the ID scheme: changing it would orphan analysts' investigation notes.
        records = [conn(n, "203.0.113.66", "192.0.2.20", 1000 + n, state="REJ", uid=f"CREGRESSION{n:04d}")
                   for n in range(15)]
        self.assertEqual(detect(records, ("NW-001",))[0].alert_id, "NW-001-e76a1be8a006")

    def test_explanations_describe_possibilities_not_certainties(self):
        for alert in detect(self.mixed()):
            with self.subTest(rule=alert.rule_id):
                text = alert.explanation.lower()
                self.assertNotIn("confirmed", text)
                self.assertNotIn("attack detected", text)
                if alert.window_seconds:
                    self.assertIn("threshold", text)


# ---------------------------------------------------------------------------
# Synthetic log files, end to end
# ---------------------------------------------------------------------------

EXPECTED_DEMO_ALERTS = [
    # (rule, severity, source, destination, ports, supporting connections)
    ("NW-003", "Low", "192.0.2.14", "198.51.100.25", (3389,), 1),
    ("NW-001", "High", "203.0.113.66", "192.0.2.20", None, 60),
    ("NW-002", "Low", "192.0.2.30", "192.0.2.53", (53,), 120),
    ("NW-003", "Low", "192.0.2.12", "203.0.113.80", (4444,), 3),
    ("NW-004", "High", "203.0.113.99", "192.0.2.26", (22,), 36),
    ("NW-004", "Medium", "192.0.2.11", "198.51.100.70", (8080,), 12),
]


class SyntheticLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tsv_alerts = det.run_detection(an.load_log(DEMO_TSV).connections)

    def test_demo_produces_the_documented_alerts(self):
        actual = [(a.rule_id, a.severity, a.src_ip, a.dst_ip, a.dst_ports if a.rule_id != "NW-001" else None,
                   a.connection_count) for a in self.tsv_alerts]
        self.assertEqual(actual, EXPECTED_DEMO_ALERTS)
        self.assertEqual(len(self.tsv_alerts[1].dst_ports), 60)

    def test_tsv_and_json_give_identical_alerts(self):
        self.assertEqual(self.tsv_alerts, det.run_detection(an.load_log(DEMO_JSON).connections))

    def test_shuffled_log_lines_give_identical_alerts(self):
        lines = DEMO_JSON.read_text(encoding="utf-8").splitlines()
        random.Random(42).shuffle(lines)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "shuffled.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertEqual(det.run_detection(an.load_log(path).connections), self.tsv_alerts)

    def test_normal_traffic_raises_no_alerts(self):
        self.assertEqual(det.run_detection(an.load_log(NORMAL).connections), [])

    def test_supporting_events_exist_in_the_log(self):
        event_ids = set(an.load_log(DEMO_TSV).connections["event_id"])
        for alert in self.tsv_alerts:
            with self.subTest(alert=alert.alert_id):
                self.assertTrue(set(alert.event_ids) <= event_ids)
                self.assertEqual(len(alert.event_ids), alert.connection_count)


class MainTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = det.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_demo(self):
        code, out, _ = self.run_main([str(DEMO_TSV)])
        self.assertEqual(code, 0)
        self.assertIn("Alerts:  6 (High 2, Medium 1, Low 3)", out)
        self.assertIn("not confirmed attacks", out)
        out.encode("ascii")  # plain ASCII, safe for any Windows console code page

    def test_normal_traffic(self):
        code, out, _ = self.run_main([str(NORMAL)])
        self.assertEqual(code, 0)
        self.assertIn("No alerts", out)

    def test_options(self):
        _, out, _ = self.run_main([str(DEMO_TSV), "--rules", "NW-003", "--watchlist", "3389"])
        self.assertIn("Alerts:  1 (High 0, Medium 0, Low 1)", out)

    def test_bad_arguments(self):
        for argv in (["x.log", "--watchlist", "abc"], ["x.log", "--rules", "NW-999"], ["x.log", "--scan-ports", "0"]):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
                    det.main(argv)
                self.assertEqual(ctx.exception.code, 2)

    def test_missing_file(self):
        code, _, err = self.run_main(["missing.log"])
        self.assertEqual(code, 1)
        self.assertIn("not found", err)


if __name__ == "__main__":
    unittest.main()
