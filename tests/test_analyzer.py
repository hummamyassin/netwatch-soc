"""Tests for netwatch.analyzer (pandas traffic analysis).

Run with:  python -m unittest -v
"""

import contextlib
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from pandas.testing import assert_frame_equal

from netwatch import analyzer as an
from netwatch.zeek_conn import ConnRecord, parse_conn_log

FIXTURES = Path(__file__).parent / "fixtures" / "zeek"
BASE = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def conn(seconds: float = 0, src: str = "192.0.2.1", dst: str = "198.51.100.1",
         dport: int | None = 80, proto: str | None = "tcp", state: str | None = "SF",
         uid: str | None = None, duration: float | None = None,
         orig_bytes: int | None = None, resp_bytes: int | None = None) -> ConnRecord:
    """A synthetic connection `seconds` after BASE. Unspecified values are missing."""
    return ConnRecord(
        ts=BASE + timedelta(seconds=seconds), uid=uid, src_ip=src, src_port=50000 if dport else None,
        dst_ip=dst, dst_port=dport, proto=proto, service=None, duration=duration,
        orig_bytes=orig_bytes, resp_bytes=resp_bytes, orig_pkts=None, resp_pkts=None,
        conn_state=state, history=None,
    )


def frame_of(*records: ConnRecord) -> pd.DataFrame:
    return an.records_to_dataframe(list(records))


class DataFrameTests(unittest.TestCase):
    def test_column_types(self):
        frame = frame_of(conn(uid="Cabc", duration=1.5, orig_bytes=10))
        self.assertEqual(list(frame.columns), an.COLUMNS)
        self.assertEqual(str(frame["ts"].dtype), "datetime64[us, UTC]")
        self.assertEqual(str(frame["dst_port"].dtype), "Int64")
        self.assertEqual(str(frame["orig_bytes"].dtype), "Int64")
        self.assertEqual(str(frame["duration"].dtype), "Float64")
        self.assertEqual(frame["src_ip"].dtype, object)

    def test_missing_values_stay_missing(self):
        frame = frame_of(conn(orig_bytes=None, duration=None, state=None))
        self.assertTrue(pd.isna(frame.loc[0, "orig_bytes"]))
        self.assertTrue(pd.isna(frame.loc[0, "duration"]))
        self.assertIsNone(frame.loc[0, "conn_state"])

    def test_event_ids_use_uid_or_position(self):
        frame = frame_of(conn(uid="CAAA"), conn(uid=None), conn(uid="CBBB"))
        self.assertEqual(frame["event_id"].tolist(), ["CAAA", "row-2", "CBBB"])

    def test_empty_records_give_typed_empty_frame(self):
        frame = an.records_to_dataframe([])
        self.assertTrue(frame.empty)
        self.assertEqual(list(frame.columns), an.COLUMNS)
        self.assertEqual(str(frame["ts"].dtype), "datetime64[us, UTC]")

    def test_timestamps_are_utc(self):
        # +02:00 in the source must become 10:00 UTC, not 12:00.
        local = datetime(2025, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=2)))
        record = conn()
        record.ts = local
        frame = frame_of(record)
        self.assertEqual(frame.loc[0, "ts"], pd.Timestamp("2025-01-01 10:00:00", tz="UTC"))

    def test_far_future_timestamp_does_not_crash(self):
        record = conn()
        record.ts = datetime(5000, 1, 1, tzinfo=timezone.utc)  # beyond pandas' nanosecond range
        self.assertEqual(frame_of(record).loc[0, "ts"].year, 5000)

    def test_tsv_and_json_fixtures_give_identical_frames(self):
        tsv = an.load_log(FIXTURES / "conn_tsv.log").connections
        json_ = an.load_log(FIXTURES / "conn_json.log").connections
        assert_frame_equal(tsv, json_)


class DuplicateTests(unittest.TestCase):
    def test_repeated_uid_is_removed(self):
        frame = frame_of(conn(uid="CAAA"), conn(seconds=1, uid="CBBB"), conn(seconds=2, uid="CAAA"))
        deduped, removed = an.drop_duplicate_events(frame)
        self.assertEqual(removed, 1)
        self.assertEqual(deduped["event_id"].tolist(), ["CAAA", "CBBB"])

    def test_rows_without_uid_are_never_duplicates(self):
        frame = frame_of(conn(), conn())  # identical, but no uid: row-1, row-2
        self.assertEqual(an.drop_duplicate_events(frame)[1], 0)

    def test_log_appended_to_itself(self):
        text = (FIXTURES / "conn_json.log").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doubled.log"
            path.write_text(text + text, encoding="utf-8")
            loaded = an.load_log(path)
        self.assertEqual(an.total_connections(loaded.connections), 6)
        self.assertEqual(loaded.duplicates_removed, 6)


class EmptyDatasetTests(unittest.TestCase):
    def setUp(self):
        self.frame = an.records_to_dataframe([])

    def test_counts_are_zero(self):
        self.assertEqual(an.total_connections(self.frame), 0)
        self.assertEqual(an.unique_source_ips(self.frame), 0)
        self.assertEqual(an.unique_destination_ips(self.frame), 0)
        self.assertIsNone(an.time_range(self.frame))

    def test_tables_are_empty_not_errors(self):
        for table in [an.protocol_distribution(self.frame), an.top_source_ips(self.frame),
                      an.top_destination_ports(self.frame), an.connection_state_distribution(self.frame)]:
            with self.subTest(columns=list(table.columns)):
                self.assertTrue(table.empty)
                self.assertIn("connections", table.columns)

    def test_bytes_and_duration(self):
        self.assertEqual(an.byte_totals(self.frame).total, 0)
        self.assertIsNone(an.duration_stats(self.frame).average_seconds)

    def test_timeline(self):
        timeline, bucket = an.connections_over_time(self.frame)
        self.assertTrue(timeline.empty)
        self.assertEqual(list(timeline.columns), ["time", "connections"])

    def test_report(self):
        self.assertIn("No connections to analyse", an.format_report(
            an.LoadedLog(result=parse_conn_log(FIXTURES / "conn_tsv.log"), connections=self.frame,
                         duplicates_removed=0)))


class CountingTests(unittest.TestCase):
    def test_unique_ips(self):
        frame = frame_of(conn(src="192.0.2.1", dst="198.51.100.1"), conn(src="192.0.2.1", dst="198.51.100.2"),
                         conn(src="192.0.2.9", dst="198.51.100.1"))
        self.assertEqual(an.unique_source_ips(frame), 2)
        self.assertEqual(an.unique_destination_ips(frame), 2)

    def test_protocol_distribution(self):
        frame = frame_of(conn(proto="tcp"), conn(proto="tcp"), conn(proto="udp", dport=53),
                         conn(proto="icmp", dport=None), conn(proto=None))
        table = an.protocol_distribution(frame)
        self.assertEqual(table["proto"].tolist(), ["tcp", an.NOT_RECORDED, "icmp", "udp"])
        self.assertEqual(table["connections"].tolist(), [2, 1, 1, 1])
        self.assertEqual(table["percent"].tolist(), [40.0, 20.0, 20.0, 20.0])

    def test_top_source_ips_ties_use_numeric_ip_order(self):
        frame = frame_of(conn(src="10.0.0.10"), conn(src="10.0.0.2"), conn(src="2001:db8::1"),
                         conn(src="10.0.0.9"), conn(src="10.0.0.9"))
        table = an.top_source_ips(frame)
        # 10.0.0.9 has most; then ties in numeric order, IPv4 before IPv6.
        self.assertEqual(table["src_ip"].tolist(), ["10.0.0.9", "10.0.0.2", "10.0.0.10", "2001:db8::1"])
        self.assertEqual(an.top_source_ips(frame, n=2)["src_ip"].tolist(), ["10.0.0.9", "10.0.0.2"])

    def test_top_destination_ports_per_protocol(self):
        frame = frame_of(conn(dport=53, proto="udp"), conn(dport=53, proto="udp"), conn(dport=53, proto="tcp"),
                         conn(dport=443), conn(dport=22), conn(dport=None, proto="icmp"))
        table = an.top_destination_ports(frame)
        self.assertEqual(list(zip(table["dst_port"], table["proto"], table["connections"])),
                         [(53, "udp", 2), (22, "tcp", 1), (53, "tcp", 1), (443, "tcp", 1)])

    def test_connection_states(self):
        frame = frame_of(conn(state="SF"), conn(state="S0"), conn(state="S0"), conn(state=None), conn(state="XYZ"))
        table = an.connection_state_distribution(frame)
        self.assertEqual(table["conn_state"].tolist(), ["S0", an.NOT_RECORDED, "SF", "XYZ"])
        described = dict(zip(table["conn_state"], table["description"]))
        self.assertEqual(described["S0"], "Attempt seen, no reply")
        self.assertEqual(described[an.NOT_RECORDED], "Zeek did not record a state")
        self.assertEqual(described["XYZ"], "Unknown state")
        self.assertTrue(an.has_connection_states(frame))
        self.assertFalse(an.has_connection_states(frame_of(conn(state=None))))

    def test_missing_bytes_are_not_counted_as_zero(self):
        frame = frame_of(conn(orig_bytes=None, resp_bytes=None), conn(orig_bytes=0, resp_bytes=0),
                         conn(orig_bytes=100, resp_bytes=None))
        totals = an.byte_totals(frame)
        self.assertEqual((totals.orig_bytes, totals.resp_bytes, totals.total), (100, 0, 100))
        self.assertEqual(totals.connections_with_orig, 2)  # the explicit 0 counts, the missing one does not
        self.assertEqual(totals.connections_with_resp, 1)
        self.assertEqual(totals.connections, 3)

    def test_average_duration_ignores_missing(self):
        stats = an.duration_stats(frame_of(conn(duration=1.0), conn(duration=None), conn(duration=3.0)))
        self.assertEqual(stats.average_seconds, 2.0)
        self.assertEqual((stats.connections_with_duration, stats.connections), (2, 3))
        self.assertIsNone(an.duration_stats(frame_of(conn(duration=None))).average_seconds)


class TimelineTests(unittest.TestCase):
    def test_bucket_choice(self):
        self.assertEqual(an.choose_time_bucket(0), "1s")
        self.assertEqual(an.choose_time_bucket(60), "1s")      # 60 one-second buckets
        self.assertEqual(an.choose_time_bucket(61), "5s")
        self.assertEqual(an.choose_time_bucket(3600), "1min")
        self.assertEqual(an.choose_time_bucket(86400), "30min")
        ten_years = 10 * 365 * 86400                                    # beyond 7-day buckets
        self.assertEqual(an.choose_time_bucket(ten_years), "5256000s")   # ten_years / 60
        self.assertLessEqual(ten_years / 5256000, an.MAX_TIME_BUCKETS)

    def test_quiet_periods_are_zero(self):
        frame = frame_of(conn(seconds=0), conn(seconds=10), conn(seconds=150))
        timeline, bucket = an.connections_over_time(frame, bucket="1min")
        self.assertEqual(bucket, "1min")
        self.assertEqual(timeline["connections"].tolist(), [2, 0, 1])
        self.assertEqual(timeline["time"].iloc[0], pd.Timestamp("2025-01-01 12:00:00", tz="UTC"))
        self.assertEqual(str(timeline["time"].dt.tz), "UTC")

    def test_unsorted_input_gives_same_timeline(self):
        ordered = frame_of(conn(seconds=0), conn(seconds=70), conn(seconds=140))
        shuffled = frame_of(conn(seconds=140), conn(seconds=0), conn(seconds=70))
        assert_frame_equal(an.connections_over_time(ordered)[0], an.connections_over_time(shuffled)[0])


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.frame = an.load_log(FIXTURES / "conn_tsv.log").connections

    def test_fixture_numbers(self):
        self.assertEqual(an.total_connections(self.frame), 6)
        self.assertEqual(an.unique_source_ips(self.frame), 2)
        self.assertEqual(an.unique_destination_ips(self.frame), 4)
        totals = an.byte_totals(self.frame)
        self.assertEqual((totals.orig_bytes, totals.resp_bytes), (668, 2224))
        self.assertEqual(totals.connections_with_orig, 5)  # the S0 connection has no byte count
        self.assertAlmostEqual(an.duration_stats(self.frame).average_seconds, 0.2801)

    def test_icmp_is_not_in_port_table(self):
        ports = an.top_destination_ports(self.frame)
        self.assertNotIn("icmp", ports["proto"].tolist())
        self.assertEqual(ports["connections"].sum(), 5)


class HelperTests(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(an.human_bytes(0), "0 B")
        self.assertEqual(an.human_bytes(1023), "1023 B")
        self.assertEqual(an.human_bytes(1536), "1.5 KB")
        self.assertEqual(an.human_bytes(5 * 1024 ** 3), "5.0 GB")

    def test_human_span(self):
        self.assertEqual(an.human_span(5.8), "5.8 s")
        self.assertEqual(an.human_span(125), "2m 05s")
        self.assertEqual(an.human_span(3725), "1h 02m 05s")


class MainTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = an.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_report_on_fixture(self):
        code, out, err = self.run_main([str(FIXTURES / "conn_json.log"), "--top", "3"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("Connections:     6 (0 line(s) skipped, 0 duplicate(s) removed)", out)
        self.assertIn("Top 3 source IPs", out)
        self.assertIn("(5 of 6 connections recorded)", out)

    def test_missing_file(self):
        code, _, err = self.run_main(["does-not-exist.log"])
        self.assertEqual(code, 1)
        self.assertIn("not found", err)


if __name__ == "__main__":
    unittest.main()
