"""Tests for netwatch.pcap_inspect.

Run with:  python -m unittest -v

Most tests do NOT need tshark: they check input validation, parsing, and
error handling using fake ("mocked") tshark results. One test at the end
runs real tshark on a tiny synthetic capture and is skipped if tshark is
not installed.
"""

import argparse
import contextlib
import io
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netwatch import pcap_inspect as pi


def tsv(*values: str) -> str:
    """Build one fake tshark output line in TSHARK_FIELDS order."""
    return "\t".join(values)


class TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def make_file(self, name: str, content: bytes = b"not really a pcap") -> Path:
        path = self.tmp / name
        path.write_bytes(content)
        return path


class ValidateCapturePathTests(TempDirTestCase):
    def test_missing_file_is_rejected(self):
        with self.assertRaisesRegex(pi.InspectError, "not found"):
            pi.validate_capture_path(str(self.tmp / "nope.pcap"))

    def test_directory_is_rejected(self):
        with self.assertRaisesRegex(pi.InspectError, "Not a file"):
            pi.validate_capture_path(str(self.tmp))

    def test_empty_file_is_rejected(self):
        path = self.make_file("empty.pcap", b"")
        with self.assertRaisesRegex(pi.InspectError, "empty"):
            pi.validate_capture_path(str(path))

    def test_existing_file_returns_absolute_path(self):
        path = self.make_file("ok.pcap")
        result = pi.validate_capture_path(str(path))
        self.assertTrue(result.is_absolute())
        self.assertEqual(result, path.resolve())


class LimitArgumentTests(unittest.TestCase):
    def test_valid_limits(self):
        self.assertEqual(pi.positive_limit("1"), 1)
        self.assertEqual(pi.positive_limit(str(pi.MAX_LIMIT)), pi.MAX_LIMIT)

    def test_invalid_limits(self):
        for bad in ["0", "-5", "abc", "1.5", str(pi.MAX_LIMIT + 1)]:
            with self.subTest(value=bad):
                with self.assertRaises(argparse.ArgumentTypeError):
                    pi.positive_limit(bad)

    def test_parser_exits_on_bad_limit(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                pi.build_arg_parser().parse_args(["file.pcap", "--limit", "0"])
        self.assertEqual(ctx.exception.code, 2)

    def test_parser_exits_when_capture_missing(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pi.build_arg_parser().parse_args([])


class FindTsharkTests(unittest.TestCase):
    def test_uses_path_when_available(self):
        with mock.patch("shutil.which", return_value="/usr/bin/tshark"):
            self.assertEqual(pi.find_tshark(), "/usr/bin/tshark")

    def test_returns_none_when_not_installed(self):
        with mock.patch("shutil.which", return_value=None), \
             mock.patch.dict("os.environ", {"ProgramFiles": "Z:\\does-not-exist"}):
            self.assertIsNone(pi.find_tshark())


class BuildCommandTests(unittest.TestCase):
    def test_command_is_a_safe_argument_list(self):
        # A file name full of shell characters must stay ONE argument.
        tricky = Path("evil; rm -rf ~ & calc.exe.pcap")
        command = pi.build_tshark_command("tshark", tricky, 5)

        self.assertIsInstance(command, list)
        self.assertIn(str(tricky), command)
        self.assertEqual(command[command.index("-r") + 1], str(tricky))
        self.assertEqual(command[command.index("-c") + 1], "5")
        self.assertIn("-n", command)  # no DNS lookups while reading

    def test_requests_every_field(self):
        command = pi.build_tshark_command("tshark", Path("x.pcap"), 1)
        requested = [command[i + 1] for i, arg in enumerate(command) if arg == "-e"]
        self.assertEqual(requested, pi.TSHARK_FIELDS)


class RunTsharkTests(unittest.TestCase):
    def fake_result(self, returncode: int, stdout: str = "", stderr: str = ""):
        return subprocess.CompletedProcess(["tshark"], returncode, stdout, stderr)

    def test_never_uses_shell(self):
        with mock.patch("subprocess.run", return_value=self.fake_result(0, "x")) as run:
            pi.run_tshark(["tshark", "-r", "a.pcap"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_failure_without_output_raises(self):
        result = self.fake_result(2, stderr="The file isn't a capture file")
        with mock.patch("subprocess.run", return_value=result):
            with self.assertRaisesRegex(pi.InspectError, "isn't a capture file"):
                pi.run_tshark(["tshark"])

    def test_failure_with_partial_output_warns(self):
        result = self.fake_result(2, stdout="line\n", stderr="cut short in the middle")
        with mock.patch("subprocess.run", return_value=result):
            stdout, warning = pi.run_tshark(["tshark"])
        self.assertEqual(stdout, "line\n")
        self.assertIn("partial", warning)

    def test_timeout_raises(self):
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 60)):
            with self.assertRaisesRegex(pi.InspectError, "longer than"):
                pi.run_tshark(["tshark"])

    def test_program_vanished_raises(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(pi.InspectError, "Could not start"):
                pi.run_tshark(["tshark"])


class ParseTests(unittest.TestCase):
    def test_ipv4_tcp(self):
        line = tsv("1700000000.5", "10.0.0.1", "", "10.0.0.2", "", "eth:ethertype:ip:tcp",
                   "51000", "", "443", "", "66")
        p = pi.parse_tshark_line(line)
        self.assertEqual(p.timestamp, "2023-11-14 22:13:20.500 UTC")
        self.assertEqual((p.src_ip, p.dst_ip), ("10.0.0.1", "10.0.0.2"))
        self.assertEqual(p.protocol, "TCP")
        self.assertEqual((p.src_port, p.dst_port), ("51000", "443"))
        self.assertEqual(p.length, "66")

    def test_ipv6_udp_dns(self):
        line = tsv("1700000000", "", "fe80::1", "", "ff02::fb", "eth:ethertype:ipv6:udp:dns",
                   "", "5353", "", "5353", "90")
        p = pi.parse_tshark_line(line)
        self.assertEqual((p.src_ip, p.dst_ip), ("fe80::1", "ff02::fb"))
        self.assertEqual(p.protocol, "DNS")
        self.assertEqual((p.src_port, p.dst_port), ("5353", "5353"))

    def test_icmp_has_no_ports(self):
        line = tsv("1700000000", "10.0.0.1", "", "8.8.8.8", "", "eth:ethertype:ip:icmp:data",
                   "", "", "", "", "98")
        p = pi.parse_tshark_line(line)
        self.assertEqual((p.src_port, p.dst_port), (pi.MISSING, pi.MISSING))

    def test_arp_has_no_ip_or_ports(self):
        line = tsv("1700000000", "", "", "", "", "eth:ethertype:arp", "", "", "", "", "42")
        p = pi.parse_tshark_line(line)
        self.assertEqual(p.protocol, "ARP")
        self.assertEqual((p.src_ip, p.dst_ip), (pi.MISSING, pi.MISSING))

    def test_generic_data_layer_is_not_the_protocol(self):
        # Found in a real loopback capture: Wireshark shows TCP / HTTP, not "DATA".
        cases = {
            "null:ip:tcp:data": "TCP",
            "null:ipv6:tcp:data": "TCP",
            "null:ip:tcp:http:data": "HTTP",
            "null:ip:udp:data": "UDP",
            "eth:ethertype:ip:icmp:data": "ICMP",
            "data": "DATA",  # nothing else known: keep it rather than show '-'
        }
        for stack, expected in cases.items():
            with self.subTest(stack=stack):
                self.assertEqual(pi.top_protocol(stack), expected)

    def test_short_or_garbled_line_does_not_crash(self):
        p = pi.parse_tshark_line("not-a-number")
        self.assertEqual(p.timestamp, "not-a-number")
        self.assertEqual(p.protocol, pi.MISSING)
        self.assertEqual(p.length, pi.MISSING)

    def test_blank_lines_are_skipped(self):
        output = "\n" + tsv("1", "1.1.1.1", "", "2.2.2.2", "", "ip", "", "", "", "", "60") + "\n\n"
        self.assertEqual(len(pi.parse_tshark_output(output)), 1)


class MainTests(TempDirTestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pi.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_missing_file_returns_error(self):
        code, _, err = self.run_main([str(self.tmp / "missing.pcap")])
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_tshark_missing_returns_helpful_error(self):
        path = self.make_file("a.pcap")
        with mock.patch.object(pi, "find_tshark", return_value=None):
            code, _, err = self.run_main([str(path)])
        self.assertEqual(code, 1)
        self.assertIn("tshark was not found", err)
        self.assertIn("Wireshark", err)

    def test_success_prints_table(self):
        path = self.make_file("a.pcap")
        fake_output = tsv("1700000000", "10.0.0.1", "", "10.0.0.2", "", "eth:ip:udp",
                          "1234", "", "53", "", "70") + "\n"
        with mock.patch.object(pi, "find_tshark", return_value="tshark"), \
             mock.patch.object(pi, "run_tshark", return_value=(fake_output, "")):
            code, out, _ = self.run_main([str(path), "--limit", "3"])
        self.assertEqual(code, 0)
        self.assertIn("Showing 1 packet(s)", out)
        self.assertIn("10.0.0.1", out)


def write_synthetic_pcap(path: Path) -> None:
    """Write a 1-packet pcap built by hand: Ethernet / IPv4 / UDP 1234 -> 53.

    The packet is made up (documentation IP ranges, no payload). It is not
    real traffic and is only written to a temporary folder.
    """
    udp = struct.pack("!HHHH", 1234, 53, 8, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    frame = eth + ip + udp
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", 1700000000, 0, len(frame), len(frame))
    path.write_bytes(global_header + record_header + frame)


def write_mixed_pcap(path: Path) -> None:
    """Write 6 made-up packets: DNS query, TCP SYN, SYN-ACK, ICMP ping, ARP, malformed DNS.

    Documentation addresses only (192.0.2.0/24, 198.51.100.0/24); no real traffic.
    """
    mac_a, mac_b = b"\x02\x00\x00\x00\x00\x0a", b"\x02\x00\x00\x00\x00\x14"

    def eth(payload: bytes, ethertype: int = 0x0800, src: bytes = mac_a, dst: bytes = mac_b) -> bytes:
        return dst + src + struct.pack("!H", ethertype) + payload

    def ip(src: str, dst: str, proto: int, payload: bytes) -> bytes:
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                           bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + payload

    def udp(sport: int, dport: int, data: bytes) -> bytes:
        return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data

    def tcp(sport: int, dport: int, flags: int) -> bytes:
        return struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, flags, 65535, 0, 0)

    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac_a, bytes([192, 0, 2, 10]), b"\x00" * 6,
                      bytes([192, 0, 2, 1]))
    packets = [
        eth(ip("192.0.2.10", "192.0.2.53", 17, udp(53001, 53, query))),
        eth(ip("192.0.2.10", "198.51.100.20", 6, tcp(50000, 443, 0x02))),
        eth(ip("198.51.100.20", "192.0.2.10", 6, tcp(443, 50000, 0x12)), src=mac_b, dst=mac_a),
        eth(ip("192.0.2.10", "198.51.100.1", 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping")),
        eth(arp, ethertype=0x0806, dst=b"\xff" * 6),
        eth(ip("192.0.2.10", "192.0.2.53", 17, udp(53002, 53, b"\x12\x34\x01"))),  # truncated DNS
    ]
    records = b"".join(struct.pack("<IIII", 1741593600 + n, 0, len(p), len(p)) + p for n, p in enumerate(packets))
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + records)


@unittest.skipIf(pi.find_tshark() is None, "tshark not installed")
class RealTsharkTests(TempDirTestCase):
    def test_reads_mixed_synthetic_capture(self):
        capture = self.tmp / "mixed.pcap"
        write_mixed_pcap(capture)
        output, warning = pi.run_tshark(pi.build_tshark_command(pi.find_tshark(), capture, 10))
        rows = [(p.src_ip, p.dst_ip, p.protocol, p.src_port, p.dst_port, p.length)
                for p in pi.parse_tshark_output(output)]
        self.assertEqual(warning, "")
        self.assertEqual(rows, [
            ("192.0.2.10", "192.0.2.53", "DNS", "53001", "53", "71"),
            ("192.0.2.10", "198.51.100.20", "TCP", "50000", "443", "54"),
            ("198.51.100.20", "192.0.2.10", "TCP", "443", "50000", "54"),
            ("192.0.2.10", "198.51.100.1", "ICMP", "-", "-", "46"),   # ICMP has no ports
            ("-", "-", "ARP", "-", "-", "42"),                        # ARP has no IP header
            ("192.0.2.10", "192.0.2.53", "DNS", "53002", "53", "45"),  # malformed, still labelled DNS
        ])

    def test_reads_synthetic_capture(self):
        capture = self.tmp / "synthetic.pcap"
        write_synthetic_pcap(capture)
        command = pi.build_tshark_command(pi.find_tshark(), capture, 10)
        output, _ = pi.run_tshark(command)
        packets = pi.parse_tshark_output(output)

        self.assertEqual(len(packets), 1)
        p = packets[0]
        self.assertEqual((p.src_ip, p.dst_ip), ("192.0.2.1", "198.51.100.2"))
        self.assertEqual((p.src_port, p.dst_port), ("1234", "53"))
        self.assertEqual(p.length, "42")


if __name__ == "__main__":
    unittest.main()
