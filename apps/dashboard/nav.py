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
        NavItem("Readers"),
    ]),
    NavSection("IP Intelligence", [
        NavItem("IP Addresses", "ips:list"),
        NavItem("Countries"),
        NavItem("ASNs"),
        NavItem("WHOIS"),
    ]),
    NavSection("503 Intelligence", [
        NavItem("Overview"),
        NavItem("IPs"),
        NavItem("Timeline"),
    ]),
    NavSection("Iran", [
        NavItem("Iranian IPs"),
        NavItem("CIDRs"),
        NavItem("Changes"),
        NavItem("Exports"),
    ]),
    NavItem("World Map"),
    NavItem("Workers"),
    NavSection("Settings", [
        NavItem("WHOIS"),
        NavItem("Retention"),
        NavItem("GeoIP"),
        NavItem("Iran CIDR Sources"),
        NavItem("Users"),
    ]),
]
