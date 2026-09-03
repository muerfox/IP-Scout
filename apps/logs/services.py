"""NginxLogReader: ties SSHService.poll_log, NginxLogParser and
IPIntelligenceService together into one incremental read-and-process
cycle (spec sections 9-11, 13, 47, 58).

ManualLogUploadService (bottom of this file) is the same parse-and-record
pipeline for logs that arrive by paste/file upload instead of by SSH-
polling a monitored Server - useful when you just want to feed IP Scout a
log file directly without setting up server discovery first.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from django.utils import timezone

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.ips.services import IPIntelligenceService, normalize_ip
from apps.servers.models import Server
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


# A pasted/uploaded log has no server to attach RequestEvent/LogSource rows
# to (both FKs are required, spec sections 9/11), so uploads are filed
# under one fixed, non-pollable Server record instead of inventing a fake
# monitored host. enabled=False keeps poll_all_log_sources (which only
# fans out to enabled servers) from ever touching it.
MANUAL_UPLOAD_SERVER_NAME = "Manual Uploads"

MAX_UPLOAD_LINES = 50_000


def get_or_create_manual_upload_server() -> Server:
    server, _ = Server.objects.get_or_create(
        name=MANUAL_UPLOAD_SERVER_NAME,
        defaults={
            "hostname": "manual-upload.local",
            "ssh_username": "n/a",
            "ssh_auth_type": Server.AuthType.PASSWORD,
            "ssh_private_key": "",
            "enabled": False,
        },
    )
    return server


@dataclass
class UploadSummary:
    lines_read: int
    events_created: int
    parse_errors: int
    new_ips: int
    truncated: bool


class ManualLogUploadService:
    """Parses pasted/uploaded log text with the same NginxLogParser +
    IPIntelligenceService pipeline NginxLogReader uses, but synchronously
    and without any SSH round trip - the log content is already fully in
    hand, there's nothing to poll."""

    @staticmethod
    def ingest(text: str, format_value: str, label: str = "") -> UploadSummary:
        raw_lines = [line for line in text.splitlines() if line.strip()]
        truncated = len(raw_lines) > MAX_UPLOAD_LINES
        if truncated:
            raw_lines = raw_lines[:MAX_UPLOAD_LINES]

        parser = NginxLogParser(format_value)
        parsed_lines: list[ParsedLine] = []
        parse_errors = 0
        for raw_line in raw_lines:
            try:
                parsed_lines.append(parser.parse_line(raw_line))
            except LogParseError as exc:
                parse_errors += 1
                logger.debug("manual upload parse error: %s", exc)
                continue

        server = get_or_create_manual_upload_server()
        log_source = LogSource.objects.create(
            server=server,
            name=label or f"upload-{timezone.now():%Y-%m-%d %H:%M:%S}",
            # Unique per LogSource(server, path) - a UUID guarantees that
            # even for two uploads given the same label back to back.
            path=f"manual-upload://{uuid.uuid4()}",
            format=format_value,
            enabled=False,
        )

        events_created = 0
        new_ip_count = 0
        if parsed_lines:
            addresses = {normalize_ip(p.remote_addr) for p in parsed_lines}
            already_known = set(
                IPAddress.objects.filter(address__in=addresses).values_list("address", flat=True)
            )
            new_ip_count = len(addresses - already_known)

            ip_map = IPIntelligenceService.record_sightings_bulk(
                [(p.remote_addr, p.timestamp) for p in parsed_lines]
            )
            events = [
                RequestEvent(
                    server_id=server.id,
                    log_source_id=log_source.id,
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
            log_source.last_event_at = max(p.timestamp for p in parsed_lines)

        log_source.last_read_at = timezone.now()
        log_source.byte_offset = len(text.encode("utf-8"))
        log_source.last_error = f"{parse_errors} line(s) failed to parse" if parse_errors else ""
        log_source.save(
            update_fields=["last_read_at", "last_event_at", "byte_offset", "last_error", "updated_at"]
        )

        return UploadSummary(
            lines_read=len(raw_lines),
            events_created=events_created,
            parse_errors=parse_errors,
            new_ips=new_ip_count,
            truncated=truncated,
        )
