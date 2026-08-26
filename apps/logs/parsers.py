"""Configurable Nginx access log parsing (spec section 10).

`LogSource.format` names a preset in NGINX_LOG_FORMATS, or - since real
deployments customize their log_format directive - can instead be a raw
nginx log_format string (with $variables) to compile directly. Either
way, NginxLogParser turns one line into a ParsedLine or raises
LogParseError.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

# Nginx $variable -> the regex fragment used to capture it. Literal text
# between variables (spaces, quotes, brackets) is taken verbatim from the
# format string and regex-escaped - see compile_format().
_TOKEN_PATTERNS: dict[str, str] = {
    "remote_addr": r"(?P<remote_addr>\S+)",
    "remote_user": r"\S+",
    "time_local": r"(?P<time_local>[^\]]+)",
    "request": r"(?P<request>[^\"]*)",
    "status": r"(?P<status>\d{3})",
    "body_bytes_sent": r"(?P<body_bytes_sent>\S+)",
    "http_referer": r"(?P<http_referer>[^\"]*)",
    "http_user_agent": r"(?P<http_user_agent>[^\"]*)",
    "request_time": r"(?P<request_time>\S+)",
    "host": r"(?P<host>\S+)",
}

_TOKEN_RE = re.compile(r"\$([a-z_]+)")

# Built-in presets. Nginx's own default `combined` format has no $host;
# many real deployments add it as the first field for multi-vhost setups.
NGINX_LOG_FORMATS: dict[str, str] = {
    "combined": (
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent"'
    ),
    "combined_host": (
        '$host $remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent"'
    ),
    "combined_timed": (
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" $request_time'
    ),
}

_REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+) (?P<uri>\S+) \S+$")


class LogParseError(Exception):
    """A line didn't match the configured format, or a field was invalid."""


@dataclass
class ParsedLine:
    remote_addr: str
    timestamp: datetime
    method: str
    uri: str
    status: int
    bytes: int
    request_time: float | None
    host: str
    user_agent: str
    referer: str
    raw_line: str


def compile_format(format_string: str) -> re.Pattern[str]:
    """Turn an nginx log_format string (containing $variables) into a
    compiled regex with one named group per recognized variable."""
    parts: list[str] = []
    pos = 0
    for match in _TOKEN_RE.finditer(format_string):
        parts.append(re.escape(format_string[pos : match.start()]))
        token = match.group(1)
        try:
            parts.append(_TOKEN_PATTERNS[token])
        except KeyError as exc:
            raise ValueError(f"Unsupported nginx log_format variable: ${token}") from exc
        pos = match.end()
    parts.append(re.escape(format_string[pos:]))
    return re.compile("^" + "".join(parts) + "$")


@lru_cache(maxsize=64)
def _compiled_pattern(format_value: str) -> re.Pattern[str]:
    format_string = NGINX_LOG_FORMATS.get(format_value, format_value)
    return compile_format(format_string)


def split_request(request: str) -> tuple[str, str]:
    """"GET /path?x=1 HTTP/1.1" -> ("GET", "/path?x=1"). Malformed/empty
    request lines (e.g. "-" for connections closed before a request was
    read) return ("", request) rather than raising."""
    match = _REQUEST_RE.match(request)
    if not match:
        return "", request
    return match.group("method"), match.group("uri")


class NginxLogParser:
    """Bound to one format (a LogSource.format value)."""

    def __init__(self, format_value: str):
        self.format_value = format_value
        self.pattern = _compiled_pattern(format_value)

    def parse_line(self, raw_line: str) -> ParsedLine:
        line = raw_line.rstrip("\r\n")
        match = self.pattern.match(line)
        if not match:
            raise LogParseError(f"Line does not match format {self.format_value!r}: {line[:200]!r}")
        groups = match.groupdict()

        remote_addr = groups.get("remote_addr", "")
        try:
            ipaddress.ip_address(remote_addr)
        except ValueError as exc:
            raise LogParseError(f"Invalid remote_addr {remote_addr!r}") from exc

        try:
            timestamp = datetime.strptime(groups["time_local"], "%d/%b/%Y:%H:%M:%S %z")
        except (KeyError, ValueError) as exc:
            raise LogParseError(f"Invalid time_local: {exc}") from exc

        try:
            status = int(groups["status"])
        except (KeyError, ValueError) as exc:
            raise LogParseError(f"Invalid status: {exc}") from exc

        try:
            bytes_sent = int(groups.get("body_bytes_sent", "0"))
        except ValueError:
            bytes_sent = 0

        request_time_raw = groups.get("request_time")
        request_time = None
        if request_time_raw and request_time_raw != "-":
            try:
                request_time = float(request_time_raw)
            except ValueError:
                request_time = None

        method, uri = split_request(groups.get("request", ""))

        return ParsedLine(
            remote_addr=remote_addr,
            timestamp=timestamp,
            method=method,
            uri=uri,
            status=status,
            bytes=bytes_sent,
            request_time=request_time,
            host=groups.get("host", ""),
            user_agent=groups.get("http_user_agent", ""),
            referer=groups.get("http_referer", ""),
            raw_line=line,
        )
