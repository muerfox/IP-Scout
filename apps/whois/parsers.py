"""Registry-agnostic WHOIS text parsing (spec section 16).

WHOIS response formats vary significantly between registries (ARIN,
RIPE, APNIC, LACNIC, AFRINIC, and national registries like IRNIC) - there
is no single schema. This parser makes no assumption that any particular
field is present:

1. `parse_generic` reads every "key: value" line into {key: [values]},
   normalizing key casing/separators but changing nothing else. This is
   what gets stored in WhoisRecord.parsed_data - lossy-free relative to
   the raw text, useful for future parser improvements even for fields
   we don't explicitly recognize today.
2. `extract_known_fields` picks the handful of canonical fields spec
   section 16 names (inetnum, netname, country, organization, descr,
   origin, route, mnt_by, abuse_email) out of that generic dict via a
   small alias table covering common registry naming conventions.
"""
from __future__ import annotations

import re
from collections import defaultdict

_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _-]*):\s?(.*)$")

# canonical field -> normalized keys (lowercase, spaces/hyphens -> "_")
# that different registries use for the same concept.
_FIELD_ALIASES: dict[str, list[str]] = {
    "inetnum": ["inetnum", "netrange", "cidr", "inet6num"],
    "netname": ["netname"],
    "country": ["country"],
    "organization": ["orgname", "org_name", "organization", "owner", "org"],
    "descr": ["descr"],
    "origin": ["origin"],
    "route": ["route", "route6"],
    "mnt_by": ["mnt_by"],
    "abuse_email": ["abuse_mailbox", "orgabuseemail", "abuse_email"],
}


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace(" ", "_").replace("-", "_")


def parse_generic(raw: str) -> dict[str, list[str]]:
    """Parse "key: value" lines into {normalized_key: [values, ...]}.

    Skips comment lines (%, #), blank lines, and anything that isn't a
    recognizable "key: value" pair rather than raising - a WHOIS response
    is never guaranteed to be well-formed.
    """
    fields: dict[str, list[str]] = defaultdict(list)
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        match = _KEY_RE.match(line)
        if not match:
            continue
        key = _normalize_key(match.group(1))
        value = match.group(2).strip()
        if not key or not value:
            continue
        fields[key].append(value)
    return dict(fields)


def extract_known_fields(parsed: dict[str, list[str]]) -> dict[str, str]:
    """Pick the canonical fields spec section 16 names out of a
    parse_generic() result. A missing field is simply absent from the
    returned dict, never guessed or defaulted."""
    result: dict[str, str] = {}
    for canonical, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            values = parsed.get(alias)
            if values:
                result[canonical] = values[0]
                break
    return result


class WhoisParser:
    """Thin wrapper tying the two steps above together for one response."""

    def parse(self, raw: str) -> tuple[dict[str, list[str]], dict[str, str]]:
        generic = parse_generic(raw)
        return generic, extract_known_fields(generic)
