"""Linux `whois` binary execution (spec sections 15, 18, 43).

subprocess.run() with an argv list - never shell=True, never string
interpolation. The address is validated with ipaddress.ip_address()
before it's ever passed to the binary; the only other explicit operation
this service exposes is routing that same subprocess through a SOCKS
proxy via proxychains-ng, when the caller passes one (see
apps.whois.proxies.ProxyPool and apps.whois.models.ProxyEndpoint) - no
arbitrary command execution either way.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings

if TYPE_CHECKING:
    from .models import ProxyEndpoint


@dataclass
class WhoisLookupResult:
    success: bool
    raw_response: str = ""
    error: str = ""
    # True for failures worth retrying (timeout, couldn't spawn the
    # process) - False for failures that won't change on retry (invalid
    # input, binary missing, empty response).
    retryable: bool = False


class WhoisService:
    def __init__(self, binary: str | None = None, timeout: int | None = None):
        self.binary = self._resolve_binary(binary or settings.WHOIS_BINARY)
        self.timeout = timeout if timeout is not None else settings.WHOIS_TIMEOUT

    @staticmethod
    def _resolve_binary(configured: str) -> str:
        """Prefer the configured path; fall back to a PATH lookup if it
        doesn't exist there (spec section 15: "detect the location of the
        binary, preferably /usr/bin/whois but allow configuration")."""
        if Path(configured).exists():
            return configured
        found = shutil.which("whois")
        return found or configured

    def lookup(self, address: str, proxy: ProxyEndpoint | None = None) -> WhoisLookupResult:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return WhoisLookupResult(success=False, error=f"Invalid IP address: {address!r}")

        if not Path(self.binary).exists():
            return WhoisLookupResult(
                success=False,
                error=f"whois binary not found at {self.binary!r} (set WHOIS_BINARY)",
            )

        argv = [self.binary, address]
        conf_path: Path | None = None
        if proxy is not None:
            proxychains_bin = shutil.which(settings.WHOIS_PROXYCHAINS_BINARY)
            if not proxychains_bin:
                return WhoisLookupResult(
                    success=False,
                    error=(
                        f"{settings.WHOIS_PROXYCHAINS_BINARY!r} not found on PATH - install "
                        "proxychains-ng to route WHOIS lookups through a proxy"
                    ),
                )
            conf_path = self._write_proxychains_conf(proxy)
            argv = [proxychains_bin, "-f", str(conf_path), "-q", *argv]

        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, address validated above
                argv,
                capture_output=True,
                timeout=self.timeout,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return WhoisLookupResult(
                success=False, error=f"whois timed out after {self.timeout}s", retryable=True
            )
        except OSError as exc:
            return WhoisLookupResult(success=False, error=str(exc), retryable=True)
        finally:
            if conf_path is not None:
                conf_path.unlink(missing_ok=True)

        raw = (proc.stdout or "").strip()
        if not raw:
            error = (proc.stderr or "").strip() or f"whois exited {proc.returncode} with no output"
            return WhoisLookupResult(success=False, error=error)

        return WhoisLookupResult(success=True, raw_response=proc.stdout)

    @staticmethod
    def _write_proxychains_conf(proxy: ProxyEndpoint) -> Path:
        """One proxy per lookup, in a private temp file deleted right
        after the subprocess exits - proxychains-ng has no "pick one proxy
        from argv" mode, only a config file, and this is the one place a
        proxy's plaintext password (see ProxyEndpoint.password) ever
        touches disk. mkstemp defaults to mode 0600 (owner-only)."""
        proxy_type = "socks5" if proxy.scheme in ("socks5", "socks5h") else proxy.scheme
        line = f"{proxy_type} {proxy.host} {proxy.port}"
        if proxy.username:
            line += f" {proxy.username} {proxy.password}"

        lines = ["strict_chain"]
        if proxy.scheme == "socks5h":
            lines.append("proxy_dns")
        lines += ["[ProxyList]", line]

        fd, path = tempfile.mkstemp(prefix="ipscout-proxychains-", suffix=".conf")
        with os.fdopen(fd, "w") as handle:
            handle.write("\n".join(lines) + "\n")
        return Path(path)

    @staticmethod
    def response_hash(raw_response: str) -> str:
        return hashlib.sha256(raw_response.encode("utf-8", errors="replace")).hexdigest()
