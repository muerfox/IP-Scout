"""Linux `whois` binary execution (spec sections 15, 18, 43).

subprocess.run() with an argv list - never shell=True, never string
interpolation. The address is validated with ipaddress.ip_address()
before it's ever passed to the binary; this is the one and only explicit
operation this service exposes (no arbitrary command execution).
"""
from __future__ import annotations

import hashlib
import ipaddress
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings


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

    def lookup(self, address: str) -> WhoisLookupResult:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return WhoisLookupResult(success=False, error=f"Invalid IP address: {address!r}")

        if not Path(self.binary).exists():
            return WhoisLookupResult(
                success=False,
                error=f"whois binary not found at {self.binary!r} (set WHOIS_BINARY)",
            )

        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, address validated above
                [self.binary, address],
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

        raw = (proc.stdout or "").strip()
        if not raw:
            error = (proc.stderr or "").strip() or f"whois exited {proc.returncode} with no output"
            return WhoisLookupResult(success=False, error=error)

        return WhoisLookupResult(success=True, raw_response=proc.stdout)

    @staticmethod
    def response_hash(raw_response: str) -> str:
        return hashlib.sha256(raw_response.encode("utf-8", errors="replace")).hexdigest()
