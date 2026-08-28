import unittest
from datetime import timezone as dt_timezone

from .parsers import LogParseError, NginxLogParser, compile_format, split_request


class CompileFormatTests(unittest.TestCase):
    def test_unsupported_variable_raises(self):
        with self.assertRaises(ValueError):
            compile_format("$remote_addr $bogus_variable")

    def test_literal_text_is_escaped(self):
        pattern = compile_format("$status.")
        self.assertTrue(pattern.match("200."))
        self.assertIsNone(pattern.match("200x"))


class SplitRequestTests(unittest.TestCase):
    def test_normal_request(self):
        self.assertEqual(split_request("GET /path?x=1 HTTP/1.1"), ("GET", "/path?x=1"))

    def test_malformed_request_returns_empty_method(self):
        self.assertEqual(split_request("-"), ("", "-"))

    def test_empty_string(self):
        self.assertEqual(split_request(""), ("", ""))


class NginxLogParserCombinedTests(unittest.TestCase):
    def setUp(self):
        self.parser = NginxLogParser("combined")

    def test_parses_503_line(self):
        line = (
            '1.2.3.4 - - [26/Aug/2026:04:30:00 +0330] '
            '"GET /api?x=1 HTTP/1.1" 503 123 "-" "Mozilla/5.0"'
        )
        parsed = self.parser.parse_line(line)

        self.assertEqual(parsed.remote_addr, "1.2.3.4")
        self.assertEqual(parsed.method, "GET")
        self.assertEqual(parsed.uri, "/api?x=1")
        self.assertEqual(parsed.status, 503)
        self.assertEqual(parsed.bytes, 123)
        self.assertEqual(parsed.user_agent, "Mozilla/5.0")
        self.assertEqual(parsed.referer, "-")
        self.assertEqual(parsed.host, "")  # combined has no $host
        self.assertIsNone(parsed.request_time)
        self.assertEqual(parsed.timestamp.year, 2026)
        self.assertEqual(parsed.timestamp.utcoffset().total_seconds(), 3.5 * 3600)

    def test_handles_dash_request_line(self):
        line = '9.9.9.9 - - [26/Aug/2026:04:30:00 +0000] "-" 400 0 "-" "-"'
        parsed = self.parser.parse_line(line)
        self.assertEqual(parsed.method, "")
        self.assertEqual(parsed.uri, "-")

    def test_strips_trailing_newline(self):
        line = '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"\n'
        parsed = self.parser.parse_line(line)
        self.assertNotIn("\n", parsed.raw_line)

    def test_non_matching_line_raises(self):
        with self.assertRaises(LogParseError):
            self.parser.parse_line("this is not a valid access log line")

    def test_invalid_remote_addr_raises(self):
        line = 'not-an-ip - - [26/Aug/2026:04:30:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"'
        with self.assertRaises(LogParseError):
            self.parser.parse_line(line)

    def test_invalid_status_is_not_three_digits(self):
        line = '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET / HTTP/1.1" 20 1 "-" "-"'
        with self.assertRaises(LogParseError):
            self.parser.parse_line(line)


class NginxLogParserHostFormatTests(unittest.TestCase):
    def test_combined_host_extracts_host(self):
        parser = NginxLogParser("combined_host")
        line = (
            'example.com 5.1.1.1 - - [26/Aug/2026:04:30:00 +0000] '
            '"POST /submit HTTP/1.1" 503 55 "https://ref" "UA/1"'
        )
        parsed = parser.parse_line(line)
        self.assertEqual(parsed.host, "example.com")
        self.assertEqual(parsed.status, 503)


class NginxLogParserTimedFormatTests(unittest.TestCase):
    def setUp(self):
        self.parser = NginxLogParser("combined_timed")

    def test_extracts_request_time(self):
        line = (
            '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] '
            '"GET / HTTP/1.1" 503 1 "-" "-" 1.234'
        )
        parsed = self.parser.parse_line(line)
        self.assertEqual(parsed.request_time, 1.234)

    def test_dash_request_time_is_none(self):
        line = '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET / HTTP/1.1" 503 1 "-" "-" -'
        parsed = self.parser.parse_line(line)
        self.assertIsNone(parsed.request_time)


class NginxLogParserRawFormatTests(unittest.TestCase):
    """A LogSource.format that isn't a preset is compiled as a raw
    nginx log_format string directly - true "configurable formats"."""

    def test_custom_format_string(self):
        parser = NginxLogParser('$remote_addr [$time_local] $status')
        parsed = parser.parse_line("1.2.3.4 [26/Aug/2026:04:30:00 +0000] 503")
        self.assertEqual(parsed.remote_addr, "1.2.3.4")
        self.assertEqual(parsed.status, 503)
        self.assertEqual(parsed.method, "")
        self.assertEqual(parsed.uri, "")

    def test_invalid_time_local_raises(self):
        parser = NginxLogParser("$remote_addr [$time_local]")
        with self.assertRaises(LogParseError):
            parser.parse_line("1.2.3.4 [not-a-valid-date]")

    def test_format_without_status_field_raises(self):
        parser = NginxLogParser("$remote_addr [$time_local]")
        with self.assertRaises(LogParseError):
            parser.parse_line("1.2.3.4 [26/Aug/2026:04:30:00 +0000]")

    def test_non_numeric_body_bytes_sent_falls_back_to_zero(self):
        parser = NginxLogParser("$remote_addr [$time_local] $status $body_bytes_sent")
        parsed = parser.parse_line("1.2.3.4 [26/Aug/2026:04:30:00 +0000] 200 abc")
        self.assertEqual(parsed.bytes, 0)

    def test_non_numeric_request_time_falls_back_to_none(self):
        parser = NginxLogParser("$remote_addr [$time_local] $status $request_time")
        parsed = parser.parse_line("1.2.3.4 [26/Aug/2026:04:30:00 +0000] 200 abc")
        self.assertIsNone(parsed.request_time)
