"""Global search (spec section 41): "Search by IP, CIDR, ASN,
organization, country, hostname, server. IP search should immediately
show the IP intelligence page."

resolve_search() never creates a record - a search for something IP
Scout has never seen just falls through to a filtered, possibly-empty
list, exactly like any other search.
"""
from __future__ import annotations

import ipaddress

from django.db.models import Q
from django.urls import reverse

from apps.ips.models import IPAddress
from apps.servers.models import Server


def resolve_search(query: str) -> str:
    query = query.strip()
    if not query:
        return reverse("dashboard:index")

    # A bare IP address - if we've seen it, go straight to its
    # intelligence page (spec's explicit UX goal); otherwise fall
    # through to the (empty) address search rather than pretending it
    # exists.
    try:
        ipaddress.ip_address(query)
    except ValueError:
        pass
    else:
        ip = IPAddress.objects.filter(address=query).first()
        if ip:
            return reverse("ips:detail", args=[ip.pk])
        return f"{reverse('ips:list')}?q={query}"

    # A CIDR - list every known IP inside it.
    if "/" in query:
        try:
            ipaddress.ip_network(query, strict=False)
        except ValueError:
            pass
        else:
            return f"{reverse('ips:list')}?cidr={query}"

    # An ASN, optionally "AS12345" / "as12345".
    asn_candidate = query[2:] if query[:2].upper() == "AS" else query
    if asn_candidate.isdigit():
        return f"{reverse('ips:list')}?asn={asn_candidate}"

    # An exact server name or hostname match.
    server = Server.objects.filter(Q(name__iexact=query) | Q(hostname__iexact=query)).first()
    if server:
        return reverse("servers:detail", args=[server.pk])

    # Free text: address/organization/network/country on the IP list.
    return f"{reverse('ips:list')}?q={query}"
