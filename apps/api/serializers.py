"""DRF serializers (spec section 39). Every model here has its own web
UI already; these mirror what's shown there - never more than that, and
critically never `Server.ssh_private_key`, which must never leave the
server regardless of who's asking.
"""
from __future__ import annotations

from rest_framework import serializers

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.iran.models import CountryNetwork
from apps.logs.models import LogSource
from apps.servers.models import Server
from apps.whois.models import WhoisRecord


class ServerSerializer(serializers.ModelSerializer):
    connection_status = serializers.ReadOnlyField()

    class Meta:
        model = Server
        # ssh_private_key is deliberately absent - credentials never leave
        # the server via any API response, full stop.
        fields = [
            "id",
            "name",
            "hostname",
            "ip_address",
            "ssh_port",
            "ssh_username",
            "ssh_auth_type",
            "enabled",
            "connection_status",
            "log_search_paths",
            "last_connected_at",
            "last_error",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class LogSourceSerializer(serializers.ModelSerializer):
    reader_status = serializers.ReadOnlyField()
    server_name = serializers.ReadOnlyField(source="server.name")

    class Meta:
        model = LogSource
        fields = [
            "id",
            "server",
            "server_name",
            "name",
            "path",
            "format",
            "enabled",
            "inode",
            "byte_offset",
            "reader_status",
            "last_read_at",
            "last_event_at",
            "last_error",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class IPAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPAddress
        fields = [
            "id",
            "address",
            "version",
            "country_code",
            "country_name",
            "continent",
            "latitude",
            "longitude",
            "asn",
            "organization",
            "network",
            "cidr",
            "whois_status",
            "whois_checked_at",
            "whois_next_check_at",
            "whois_country",
            "whois_error",
            "is_iran",
            "iran_checked_at",
            "iran_match_cidr",
            "first_seen_at",
            "last_seen_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class RequestEventSerializer(serializers.ModelSerializer):
    ip_address = serializers.ReadOnlyField(source="ip.address")
    server_name = serializers.ReadOnlyField(source="server.name")

    class Meta:
        model = RequestEvent
        fields = [
            "id",
            "server",
            "server_name",
            "log_source",
            "ip",
            "ip_address",
            "timestamp",
            "host",
            "method",
            "uri",
            "status",
            "bytes",
            "request_time",
            "user_agent",
            "referer",
            "raw_line",
            "created_at",
        ]
        read_only_fields = fields


class WhoisRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = WhoisRecord
        fields = [
            "id",
            "ip",
            "queried_at",
            "whois_server",
            "raw_response",
            "parsed_data",
            "response_hash",
            "created_at",
        ]
        read_only_fields = fields


class CountryNetworkSerializer(serializers.ModelSerializer):
    class Meta:
        model = CountryNetwork
        fields = [
            "id",
            "country_code",
            "cidr",
            "network",
            "prefix_length",
            "source",
            "valid_from",
            "valid_until",
            "last_verified_at",
            "enabled",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
