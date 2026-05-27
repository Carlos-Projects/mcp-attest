"""HTTP utility functions with URL validation."""

from __future__ import annotations

import ipaddress
from typing import Any, cast
from urllib.parse import urlparse

import httpx

# RFC 1918 private ranges, RFC 4193 unique-local, link-local, loopback, CGNAT
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure metadata
]

# Hostnames that are always private/local
_PRIVATE_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "0.0.0.0",
}

_MAX_JSON_SIZE = 1 * 1024 * 1024  # 1 MB
_MAX_JSON_DEPTH = 10


def validate_url(url: str, allow_private: bool = False) -> str:
    """Validate a URL for SSRF safety.

    Checks:
    - Scheme must be http or https
    - Hostname must be present and valid
    - Private/reserved IPs are blocked unless allow_private=True
    - Known private hostnames (localhost) are blocked

    Returns the normalized URL or raises ValueError.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme: '{scheme}' (only http/https allowed)"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a valid hostname")

    # Check known private hostnames
    if hostname.lower() in _PRIVATE_HOSTNAMES and not allow_private:
        raise ValueError(
            f"Connection to '{hostname}' blocked (private hostname). "
            "Use --allow-private-ips to override."
        )

    # Check if hostname is a raw IP literal
    if not allow_private:
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # hostname is not an IP literal (e.g. "example.com"), let it proceed
            pass
        else:
            # hostname is an IP literal — check against private networks
            for net in _PRIVATE_NETWORKS:
                if ip in net:
                    raise ValueError(
                        f"Connection to private IP blocked: {hostname} "
                        f"(in {net}). Use --allow-private-ips to override."
                    )

    return url


def validate_json_size(data: str) -> None:
    """Validate JSON string size and approximate depth."""
    if len(data) > _MAX_JSON_SIZE:
        raise ValueError(
            f"JSON payload too large: {len(data)} bytes (max {_MAX_JSON_SIZE})"
        )
    depth = 0
    max_depth = 0
    for ch in data:
        if ch in ("{", "["):
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in ("}", "]"):
            depth -= 1
    if max_depth > _MAX_JSON_DEPTH:
        raise ValueError(
            f"JSON nesting too deep: {max_depth} levels (max {_MAX_JSON_DEPTH})"
        )


async def fetch_json(
    url: str, timeout: float = 10.0, allow_private: bool = False
) -> dict[str, Any]:
    validate_url(url, allow_private=allow_private)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())


async def post_json(
    url: str, data: dict[str, Any], timeout: float = 10.0, allow_private: bool = False
) -> dict[str, Any]:
    validate_url(url, allow_private=allow_private)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=data)
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())


async def check_server_reachable(
    url: str, timeout: float = 5.0, allow_private: bool = False
) -> bool:
    try:
        validate_url(url, allow_private=allow_private)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            return resp.status_code < 500
    except Exception:
        return False
