"""NginxLogReader: ties SSHService.poll_log, NginxLogParser and
IPIntelligenceService together into one incremental read-and-process
cycle (spec sections 9-11, 13, 47, 58).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from django.utils import timezone

from apps.incidents.models import RequestEvent
from apps.ips.services import IPIntelligenceService, normalize_ip
from apps.servers.services import SSHService

from .models import LogSource
from .parsers import LogParseError, NginxLogParser, ParsedLine

logger = logging.getLogger("ipscout.logs")


@dataclass
class PollSummary:
    events_created: int
    parse_errors: int
    lines_read: int
    rotated: bool
    file_missing: bool = False


class NginxLogReader:
    def __init__(self, log_source: LogSource):
        self.log_source = log_source

    def poll(self) -> PollSummary:
        ssh = SSHService(self.log_source.server)
        known_offset = self.log_source.byte_offset if self.log_source.inode is not None else None
        chunk = ssh.poll_log(self.log_source.path, self.log_source.inode, known_offset)

        if chunk is None:
            self.log_source.last_error = f"Log file not found: {self.log_source.path}"
            self.log_source.last_read_at = timezone.now()
            self.log_source.save(update_fields=["last_error", "last_read_at", "updated_at"])
            return PollSummary(
                events_created=0, parse_errors=0, lines_read=0, rotated=False, file_missing=True
            )

        # Only advance byte_offset past complete lines - a trailing line
        # with no terminating \n is nginx mid-write and must be re-read
        # (combined with whatever gets appended) on the next poll.
        raw_lines = chunk.data.split(b"\n")
        leftover = raw_lines.pop()
        consumed_bytes = len(chunk.data) - len(leftover)
        complete_lines = [line.decode("utf-8", errors="replace") for line in raw_lines if line]

        parser = NginxLogParser(self.log_source.format)
        parsed_lines: list[ParsedLine] = []
        parse_errors = 0
        for raw_line in complete_lines:
            try:
                parsed = parser.parse_line(raw_line)
            except LogParseError as exc:
                parse_errors += 1
                logger.debug("log_source=%s parse error: %s", self.log_source.id, exc)
                continue
            # Every successfully-parsed line is recorded regardless of
            # status - an IP's history and Iran/geo/whois enrichment
            # shouldn't depend on it happening to have 5xx'd. The 503
            # focus lives in how RequestEvent.status is queried/displayed
            # (dashboards, exports), not in what gets written here.
            parsed_lines.append(parsed)

        events_created = 0
        latest_event_at = None
        if parsed_lines:
            ip_map = IPIntelligenceService.record_sightings_bulk(
                [(p.remote_addr, p.timestamp) for p in parsed_lines]
            )
            events = [
                RequestEvent(
                    server_id=self.log_source.server_id,
                    log_source_id=self.log_source.id,
                    ip_id=ip_map[normalize_ip(parsed.remote_addr)].id,
                    timestamp=parsed.timestamp,
                    host=parsed.host[:255],
                    method=parsed.method[:16],
                    uri=parsed.uri[:2048],
                    status=parsed.status,
                    bytes=parsed.bytes,
                    request_time=parsed.request_time,
                    user_agent=parsed.user_agent[:512],
                    referer=parsed.referer[:2048],
                    raw_line=parsed.raw_line[:8192],
                )
                for parsed in parsed_lines
            ]
            RequestEvent.objects.bulk_create(events, batch_size=1000)
            events_created = len(events)
            latest_event_at = max(p.timestamp for p in parsed_lines)

        self.log_source.inode = chunk.inode
        self.log_source.byte_offset = chunk.offset + consumed_bytes
        self.log_source.last_read_at = timezone.now()
        if latest_event_at is not None:
            self.log_source.last_event_at = latest_event_at
        self.log_source.last_error = (
            f"{parse_errors} line(s) failed to parse on last read" if parse_errors else ""
        )
        self.log_source.save(
            update_fields=[
                "inode",
                "byte_offset",
                "last_read_at",
                "last_event_at",
                "last_error",
                "updated_at",
            ]
        )

        return PollSummary(
            events_created=events_created,
            parse_errors=parse_errors,
            lines_read=len(complete_lines),
            rotated=chunk.rotated,
        )
