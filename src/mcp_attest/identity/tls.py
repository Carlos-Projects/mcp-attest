"""TLS certificate-based identity verification."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from mcp_attest.models import IdentityMethod, IdentityResult


class TLSVerifier:
    """Verifies MCP server identity via TLS certificate inspection."""

    async def verify(
        self, server_url: str, identity_data: dict[str, Any]
    ) -> IdentityResult:
        parsed = urlparse(server_url)
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.TLS_CERT,
                subject=server_url,
                details={
                    "error": (
                        "Invalid server URL: no hostname found. "
                        "Use format: https://hostname[:port]"
                    )
                },
            )

        if not (0 < port < 65536):
            return IdentityResult(
                verified=False,
                method=IdentityMethod.TLS_CERT,
                subject=server_url,
                details={"error": f"Invalid port number: {port}"},
            )

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            sock = socket.create_connection((host, port), timeout=10)
            try:
                conn = ctx.wrap_socket(sock, server_hostname=host)
                cert = conn.getpeercert()
            finally:
                sock.close()

            if not cert:
                return IdentityResult(
                    verified=False,
                    method=IdentityMethod.TLS_CERT,
                    subject=server_url,
                    details={"error": "No peer certificate returned by server"},
                )

            subject = self._extract_subject(cert)
            issuer = self._extract_issuer(cert)
            valid_from, valid_to = self._extract_validity(cert)

            return IdentityResult(
                verified=True,
                method=IdentityMethod.TLS_CERT,
                subject=subject,
                issuer=issuer,
                valid_from=valid_from,
                valid_to=valid_to,
                details={
                    "chain_verified": True,
                    "hostname_matched": True,
                },
            )
        except TimeoutError:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.TLS_CERT,
                subject=server_url,
                details={"error": f"Connection timed out connecting to {host}:{port}"},
            )
        except socket.gaierror:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.TLS_CERT,
                subject=server_url,
                details={"error": f"Could not resolve hostname: {host}"},
            )
        except ssl.SSLCertVerificationError as exc:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.TLS_CERT,
                subject=server_url,
                details={
                    "error": (
                        f"TLS certificate verification failed: {exc.verify_message}"
                    )
                },
            )
        except (ssl.SSLError, OSError) as exc:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.TLS_CERT,
                subject=server_url,
                details={"error": f"TLS connection error: {exc.strerror or 'unknown'}"},
            )

    @staticmethod
    def _extract_subject(cert: dict[str, Any]) -> str:
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr, value in rdn:
                subject_parts.append(f"{attr}={value}")
        return ", ".join(subject_parts) or "unknown"

    @staticmethod
    def _extract_issuer(cert: dict[str, Any]) -> str:
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr, value in rdn:
                issuer_parts.append(f"{attr}={value}")
        return ", ".join(issuer_parts) or "unknown"

    @staticmethod
    def _extract_validity(
        cert: dict[str, Any],
    ) -> tuple[Any, Any]:
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        fmt = "%b %d %H:%M:%S %Y %Z"
        valid_from = datetime.strptime(not_before, fmt) if not_before else None
        valid_to = datetime.strptime(not_after, fmt) if not_after else None
        return valid_from, valid_to
