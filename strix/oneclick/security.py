from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """Raised when a supplied target fails safe URL preflight."""


def _host_addresses(host: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return {ipaddress.ip_address(host)}
    except ValueError:
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise TargetValidationError(f"Could not resolve target hostname {host!r}.") from exc
        addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for record in records:
            try:
                addresses.add(ipaddress.ip_address(record[4][0].split("%", 1)[0]))
            except ValueError:
                continue
        if not addresses:
            raise TargetValidationError(f"No IP addresses were resolved for {host!r}.")
        return addresses


def validate_target_url(raw: str, allow_private: bool = False) -> str:
    """Normalize an HTTP(S) URL and reject private destinations unless explicitly allowed.

    This is a preflight check, not an egress firewall. DNS can change between validation
    and connection, and browser redirects or tools may issue requests to other hosts.
    """
    value = raw.strip()
    if not value:
        raise TargetValidationError("Enter the web application URL.")
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("Target URL must use http:// or https://.")
    if not parsed.hostname:
        raise TargetValidationError("Target URL must include a hostname.")
    if parsed.username or parsed.password:
        raise TargetValidationError("Do not put credentials in the target URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("Target URL contains an invalid port.") from exc
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} and not allow_private:
        raise TargetValidationError("Local/private targets require the explicit private-target checkbox.")
    addresses = _host_addresses(host)
    if not allow_private and any(not address.is_global for address in addresses):
        raise TargetValidationError(
            "The target resolves to a private, loopback, link-local, or non-public address. "
            "Use the private-target checkbox only for a system you control."
        )
    if ":" in host:
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def origin_of(raw: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname:
        raise TargetValidationError("A full URL is required.")
    return (parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), parsed.port)


def require_same_origin(target: str, candidate: str) -> str:
    """Require signup and target pages to share scheme, hostname, and port."""
    normalized = validate_target_url(candidate, allow_private=True)
    if origin_of(target) != origin_of(normalized):
        raise TargetValidationError("Signup URL must use the exact same origin as the target URL.")
    return normalized
