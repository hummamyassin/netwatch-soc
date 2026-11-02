"""Tests for netwatch.zeek_conn.

Run with:  python -m unittest -v

No Zeek installation is needed: the tests use the synthetic logs in
tests/fixtures/zeek/ plus small inline examples written to a temp folder.
"""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netwatch import zeek_conn as zc

FIXTURES = Path(__file__).parent / "fixtures" / "zeek"
TSV_FIXTURE = FIXTURES / "conn_tsv.log"
JSON_FIXTURE = FIXTURES / "conn_json.log"

# A short TSV header used by the inline tests below.
TSV_HEADER = "\n".join([
    "#separator \\x09",
    "#unset_field\t-",
    "#empty_field\t(empty)",
    "#path\tconn",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration"
    "\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts",
])
GOOD_TSV_ROW = "1700000000.0\tC1\t192.0.2.1\t1234\t198.51.100.2\t80\ttcp\thttp\t1.5\t10\t20\tSF\tShADadFf\t3\t4"


def tsv_row(**changes: str) -> str:
    """GOOD_TSV_ROW with some columns replaced, e.g. tsv_row(orig_bytes='abc')."""
    names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
             "duration", "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]
    values = dict(zip(names, GOOD_TSV_ROW.split("\t")))
    values.update({name.replace("__", "."): value for name, value in changes.items()})
    return "\t".join(values[name] for name in names)


GOOD_JSON = {"ts": 1700000000.0, "uid": "C1", "id.orig_h": "192.0.2.1", "id.orig_p": 1234,
             "id.resp_h": "198.51.100.2", "id.resp_p": 80, "proto": "tcp", "conn_state": "SF"}


class TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, text: str, name: str = "conn.log", newline: str = "\n") -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8", newline=newline)
        return path


# ---------------------------------------------------------------------------
# The synthetic fixtures
# ---------------------------------------------------------------------------

class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tsv = zc.parse_conn_log(TSV_FIXTURE)
        cls.json = zc.parse_conn_log(JSON_FIXTURE)

    def test_formats_are_detected(self):
        self.assertEqual(self.tsv.log_format, "tsv")
        self.assertEqual(self.json.log_format, "json")

    def test_all_rows_parse_without_errors(self):
        self.assertEqual(len(self.tsv.records), 6)
        self.assertEqual(self.tsv.errors, [])
        self.assertEqual(len(self.json.records), 6)
        self.assertEqual(self.json.errors, [])

    def test_tsv_and_json_give_identical_records(self):
        self.assertEqual(self.tsv.records, self.json.records)

    def test_complete_tcp_connection(self):
        r = self.tsv.records[0]
        self.assertEqual(r.ts, datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc))
        self.assertEqual(r.uid, "CNws0000000000001")
        self.assertEqual((r.src_ip, r.src_port, r.dst_ip, r.dst_port), ("192.0.2.10", 49152, "198.51.100.20", 80))
        self.assertEqual((r.proto, r.service, r.conn_state, r.history), ("tcp", "http", "SF", "ShADadFf"))
        self.assertEqual(r.duration, 1.25)
        self.assertEqual((r.orig_bytes, r.resp_bytes, r.orig_pkts, r.resp_pkts), (512, 2048, 8, 7))
        self.assertIsNone(r.icmp_type)

    def test_types_are_python_types_not_strings(self):
        r = self.tsv.records[1]
        self.assertIsInstance(r.ts, datetime)
        self.assertIsInstance(r.src_port, int)
        self.assertIsInstance(r.duration, float)
        self.assertIsInstance(r.orig_bytes, int)

    def test_unset_values_become_none(self):
        r = self.tsv.records[2]  # S0: no reply
        self.assertEqual(r.conn_state, "S0")
        self.assertIsNone(r.service)
        self.assertIsNone(r.duration)
        self.assertIsNone(r.orig_bytes)
        self.assertIsNone(r.resp_bytes)
        self.assertEqual(r.resp_pkts, 0)  # zero is a real value, not "missing"

    def test_icmp_type_and_code_are_not_ports(self):
        r = self.tsv.records[4]
        self.assertEqual(r.proto, "icmp")
        self.assertEqual((r.src_port, r.dst_port), (None, None))
        self.assertEqual((r.icmp_type, r.icmp_code), (8, 0))

    def test_ipv6(self):
        r = self.tsv.records[5]
        self.assertEqual((r.src_ip, r.dst_ip), ("2001:db8::10", "2001:db8::fb"))


# ---------------------------------------------------------------------------
# Value converters
# ---------------------------------------------------------------------------

class ConverterTests(unittest.TestCase):
    def test_timestamps(self):
        expected = datetime(2023, 11, 14, 22, 13, 20, 500000, tzinfo=timezone.utc)
        self.assertEqual(zc.to_timestamp("1700000000.500000"), expected)
        self.assertEqual(zc.to_timestamp(1700000000.5), expected)
        self.assertEqual(zc.to_timestamp("2023-11-14T22:13:20.500000Z"), expected)
        self.assertEqual(zc.to_timestamp("2023-11-15T00:13:20.5+02:00"), expected)

    def test_bad_timestamps(self):
        for bad in ["yesterday", "", True, float("nan"), "1e400"]:
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    zc.to_timestamp(bad)

    def test_ip_addresses(self):
        self.assertEqual(zc.to_ip("192.0.2.1"), "192.0.2.1")
        self.assertEqual(zc.to_ip("2001:0db8:0000::0001"), "2001:db8::1")  # shortened
        for bad in ["999.1.1.1", "not-an-ip", "192.0.2"]:
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    zc.to_ip(bad)

    def test_counts(self):
        self.assertEqual(zc.to_count("42"), 42)
        self.assertEqual(zc.to_count(42), 42)
        self.assertEqual(zc.to_count(42.0), 42)
        for bad in ["-1", -1, "4.5", 4.5, "abc", True]:
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    zc.to_count(bad)

    def test_ports(self):
        self.assertEqual(zc.to_port("0"), 0)
        self.assertEqual(zc.to_port("65535"), 65535)
        with self.assertRaises(ValueError):
            zc.to_port("65536")

    def test_durations(self):
        self.assertEqual(zc.to_duration("0.000500"), 0.0005)
        for bad in ["-1", "abc", "inf", "nan", False]:
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    zc.to_duration(bad)

    def test_decode_separator(self):
        self.assertEqual(zc.decode_separator(" \\x09"), "\t")
        self.assertEqual(zc.decode_separator(" \\x2c"), ",")


# ---------------------------------------------------------------------------
# Whole-file problems (raise ZeekLogError)
# ---------------------------------------------------------------------------

class FileErrorTests(TempDirTestCase):
    def assert_log_error(self, path: Path, message: str) -> None:
        with self.assertRaisesRegex(zc.ZeekLogError, message):
            zc.parse_conn_log(path)

    def test_missing_file(self):
        self.assert_log_error(self.tmp / "nope.log", "not found")

    def test_directory(self):
        self.assert_log_error(self.tmp, "Not a file")

    def test_empty_and_blank_files(self):
        self.assert_log_error(self.write(""), "empty")
        self.assert_log_error(self.write("\n   \n\n"), "empty")

    def test_unrecognised_format(self):
        self.assert_log_error(self.write("hello world\n"), "Unrecognised format")

    def test_tsv_without_fields_header(self):
        self.assert_log_error(self.write("#path\tconn\n#close\tx\n"), "No '#fields' header")

    def test_data_before_fields_header(self):
        self.assert_log_error(self.write("#path\tconn\n" + GOOD_TSV_ROW + "\n"), "before any '#fields'")

    def test_other_zeek_log_is_rejected(self):
        self.assert_log_error(self.write("#separator \\x09\n#path\tdns\n#fields\tts\tquery\n"), "'dns' log")

    def test_fields_header_without_conn_columns(self):
        self.assert_log_error(self.write("#fields\tts\tquery\tanswers\n"), "Not a conn.log")


# ---------------------------------------------------------------------------
# Bad lines (skipped and reported; good lines still parsed)
# ---------------------------------------------------------------------------

class LineErrorTests(TempDirTestCase):
    def parse_tsv_rows(self, *rows: str) -> zc.ConnLogResult:
        return zc.parse_conn_log(self.write(TSV_HEADER + "\n" + "\n".join(rows) + "\n"))

    def test_bad_tsv_lines_are_skipped_with_line_numbers(self):
        result = self.parse_tsv_rows(
            GOOD_TSV_ROW,                         # line 6
            tsv_row(id__orig_h="999.0.0.1"),      # line 7
            "too\tfew\tcolumns",                  # line 8
            tsv_row(orig_bytes="lots"),           # line 9
            tsv_row(resp_bytes="-5"),             # line 10
            tsv_row(id__resp_p="70000"),          # line 11
            tsv_row(ts="-"),                      # line 12
            tsv_row(duration="soon"),             # line 13
            GOOD_TSV_ROW,                         # line 14
        )
        self.assertEqual(len(result.records), 2)
        self.assertEqual(len(result.errors), 7)
        expected = [
            ("line 7:", "id.orig_h"),
            ("line 8:", "expected 15 columns, found 3"),
            ("line 9:", "orig_bytes"),
            ("line 10:", "resp_bytes"),
            ("line 11:", "id.resp_p"),
            ("line 12:", "missing required field 'ts'"),
            ("line 13:", "duration"),
        ]
        for message, (line_label, detail) in zip(result.errors, expected):
            with self.subTest(message=message):
                self.assertTrue(message.startswith(line_label))
                self.assertIn(detail, message)

    def test_unexpected_characters_in_text_fields_are_rejected(self):
        # Genuine Zeek output never contains these. Accepting them could inject
        # terminal escape codes or Markdown links into reports and the dashboard.
        result = self.parse_tsv_rows(
            tsv_row(service="[click](http://example.com)"),   # line 6
            tsv_row(conn_state="S0\x1b[31m"),                  # line 7
            tsv_row(uid="row-1"),                              # line 8
            tsv_row(history="Sh<b>"),                          # line 9
            tsv_row(proto="tcp;rm"),                           # line 10
            GOOD_TSV_ROW,                                      # line 11
        )
        self.assertEqual(len(result.records), 1)
        self.assertEqual([e.split(":")[0] for e in result.errors],
                         ["line 6", "line 7", "line 8", "line 9", "line 10"])
        self.assertIn("field 'service'", result.errors[0])
        self.assertIn("field 'conn_state'", result.errors[1])
        self.assertNotIn("\x1b", result.errors[1])  # shown escaped, never raw

    def test_text_fields_are_normalised(self):
        r = self.parse_tsv_rows(tsv_row(service="SSL,HTTP", conn_state="sf", proto="TCP")).records[0]
        self.assertEqual((r.service, r.conn_state, r.proto), ("ssl,http", "SF", "tcp"))

    def test_empty_marker_becomes_none(self):
        result = self.parse_tsv_rows(tsv_row(service="(empty)", history="(empty)"))
        self.assertIsNone(result.records[0].service)
        self.assertIsNone(result.records[0].history)

    def test_bad_json_lines_are_skipped(self):
        lines = [
            json.dumps(GOOD_JSON),
            "{not json",
            "[1, 2, 3]",
            json.dumps({**GOOD_JSON, "id.orig_h": "nope"}),
            json.dumps({k: v for k, v in GOOD_JSON.items() if k != "id.resp_h"}),
            json.dumps({**GOOD_JSON, "orig_bytes": 12.5}),
        ]
        result = zc.parse_conn_log(self.write("\n".join(lines) + "\n"))
        self.assertEqual(len(result.records), 1)
        self.assertEqual(len(result.errors), 5)
        self.assertIn("line 2: invalid JSON", result.errors[0])
        self.assertIn("line 3: expected a JSON object", result.errors[1])
        self.assertIn("id.orig_h", result.errors[2])
        self.assertIn("missing required field 'id.resp_h'", result.errors[3])
        self.assertIn("orig_bytes", result.errors[4])


# ---------------------------------------------------------------------------
# Format details
# ---------------------------------------------------------------------------

class FormatDetailTests(TempDirTestCase):
    def test_windows_line_endings(self):
        path = self.write(TSV_HEADER + "\n" + GOOD_TSV_ROW + "\n", newline="\r\n")
        self.assertIn(b"\r\n", path.read_bytes())
        result = zc.parse_conn_log(path)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.records[0].resp_pkts, 4)  # last column has no stray '\r'

    def test_byte_order_mark_is_ignored(self):
        path = self.write("\ufeff" + json.dumps(GOOD_JSON) + "\n")
        result = zc.parse_conn_log(path)
        self.assertEqual(result.log_format, "json")
        self.assertEqual(len(result.records), 1)

    def test_json_iso_timestamps_and_extra_fields(self):
        row = {**GOOD_JSON, "ts": "2023-11-14T22:13:20.000000Z", "community_id": "1:abc", "_path": "conn"}
        result = zc.parse_conn_log(self.write(json.dumps(row) + "\n"))
        self.assertEqual(result.errors, [])
        self.assertEqual(result.records[0].ts, datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc))

    def test_json_missing_optional_fields_become_none(self):
        row = {"ts": 1700000000, "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2"}
        r = zc.parse_conn_log(self.write(json.dumps(row) + "\n")).records[0]
        self.assertIsNone(r.uid)
        self.assertIsNone(r.proto)
        self.assertIsNone(r.src_port)
        self.assertIsNone(r.duration)
        self.assertIsNone(r.conn_state)

    def test_column_order_comes_from_fields_header(self):
        text = "#fields\tid.resp_h\tts\tid.orig_h\n198.51.100.2\t1700000000\t192.0.2.1\n"
        r = zc.parse_conn_log(self.write(text)).records[0]
        self.assertEqual((r.src_ip, r.dst_ip), ("192.0.2.1", "198.51.100.2"))

    def test_header_only_log_has_no_records(self):
        result = zc.parse_conn_log(self.write(TSV_HEADER + "\n#close\tx\n"))
        self.assertEqual((result.records, result.errors), ([], []))


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

class MainTests(TempDirTestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = zc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_fixture_preview(self):
        code, out, err = self.run_main([str(TSV_FIXTURE), "--limit", "3"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("Format:  Zeek TSV", out)
        self.assertIn("Parsed:  6 connection(s), 0 line(s) skipped", out)
        self.assertIn("Showing: 3 of 6", out)
        self.assertIn("192.0.2.10:49152", out)
        self.assertIn("Normal setup and close", out)
        self.assertNotIn("2001:db8::10", out)  # row 6 is beyond the limit

    def test_ipv6_and_icmp_display(self):
        code, out, _ = self.run_main([str(JSON_FIXTURE)])
        self.assertEqual(code, 0)
        self.assertIn("[2001:db8::10]:5353", out)
        self.assertIn("icmp", out)

    def test_missing_file_exit_code(self):
        code, _, err = self.run_main([str(self.tmp / "missing.log")])
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_skipped_lines_are_reported(self):
        path = self.write(TSV_HEADER + "\n" + GOOD_TSV_ROW + "\n" + tsv_row(orig_pkts="x") + "\n")
        code, out, err = self.run_main([str(path)])
        self.assertEqual(code, 0)
        self.assertIn("skipped 1 line(s)", err)
        self.assertIn("Parsed:  1 connection(s), 1 line(s) skipped", out)

    def test_all_lines_bad_exit_code(self):
        path = self.write("{bad json\n")
        code, out, _ = self.run_main([str(path)])
        self.assertEqual(code, 1)
        self.assertIn("No valid connections", out)

    def test_bad_limit(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                zc.build_arg_parser().parse_args([str(TSV_FIXTURE), "--limit", "0"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
