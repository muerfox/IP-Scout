"""Primary navigation tree (spec section 61).

Each leaf is `(label, url_name_or_None)`. A `None` url means the page
doesn't exist yet - the template renders it disabled rather than linking
to something that 404s, per the project rule against faking functionality.
Sections get filled in as each phase lands.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NavItem:
    label: str
    url_name: str | None = None
    # Present (as None) so templates can discriminate NavItem vs NavSection
    # with a single `{% if node.items %}` check.
    items: None = None


@dataclass(frozen=True)
class NavSection:
    label: str
    items: list[NavItem] = field(default_factory=list)


NAV_TREE: list[NavItem | NavSection] = [
    NavItem("Dashboard", "dashboard:index"),
    NavSection("Servers", [
        NavItem("All Servers", "servers:list"),
        NavItem("Add Server", "servers:create"),
    ]),
    NavSection("Logs", [
        NavItem("Log Sources", "logs:list"),
        NavItem("Upload Log", "logs:upload"),
        NavItem("Readers", "logs:readers"),
    ]),
    NavSection("IP Intelligence", [
        NavItem("IP Addresses", "ips:list"),
        NavItem("Countries", "ips:countries"),
        NavItem("ASNs", "ips:asns"),
        NavItem("WHOIS", "whois:list"),
        NavItem("Networks", "whois:networks"),
        NavItem("WHOIS Proxies", "whois:proxies"),
    ]),
    NavSection("503 Intelligence", [
        NavItem("Overview", "incidents:overview"),
        NavItem("IPs", "incidents:ip-table"),
        NavItem("Timeline", "incidents:timeline"),
    ]),
    NavSection("Iran", [
        NavItem("Iranian IPs", "iran:iranian-ips"),
        NavItem("CIDRs", "iran:cidrs"),
        NavItem("Changes", "iran:changes"),
        NavItem("Exports", "iran:export"),
    ]),
    NavItem("World Map", "dashboard:map"),
    NavItem("Workers", "dashboard:workers"),
    NavSection("Settings", [
        NavItem("WHOIS", "dashboard:settings-whois"),
        NavItem("Retention", "dashboard:settings-retention"),
        NavItem("GeoIP", "dashboard:settings-geoip"),
        NavItem("Iran CIDR Sources", "dashboard:settings-iran-sources"),
        NavItem("Users", "dashboard:settings-users"),
        # Not one of spec section 61's literal five Settings items - added
        # because AuditLogEntry has existed since Phase 1 with no in-app
        # surface at all (only /admin), and "audit log surfacing" is
        # explicitly named in the Phase 9 roadmap description.
        NavItem("Audit Log", "users:audit-log"),
    ]),
]
