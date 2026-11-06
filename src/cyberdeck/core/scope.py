"""Scope guard: Cyberdeck only acts on IPs inside an allowlist (CLAUDE.md rule 3).

Default allowlist is the Hack The Box lab ranges. Users add more with ``CYBERDECK_SCOPE_EXTRA``.
There is deliberately no way to disable the check.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from urllib.parse import urlsplit

DEFAULT_SCOPE_CIDRS: tuple[str, ...] = ("10.10.0.0/16", "10.129.0.0/16")


class ScopeError(ValueError):
    """Raised when an IP is invalid or outside the allowed scope."""


@dataclass(frozen=True)
class Scope:
    networks: tuple[IPv4Network | IPv6Network, ...]

    @classmethod
    def from_cidrs(cls, cidrs: Iterable[str]) -> Scope:
        networks: list[IPv4Network | IPv6Network] = []
        for cidr in cidrs:
            try:
                networks.append(ip_network(cidr.strip(), strict=False))
            except ValueError as exc:
                raise ScopeError(f"invalid scope CIDR {cidr!r}: {exc}") from exc
        return cls(tuple(networks))

    def contains(self, ip: str) -> bool:
        try:
            addr = ip_address(ip.strip())
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def check(self, ip: str) -> str:
        """Return the normalised IP, or raise :class:`ScopeError`."""
        try:
            addr = ip_address(ip.strip())
        except ValueError:
            raise ScopeError(f"{ip!r} is not a valid IP address") from None
        if not any(addr in net for net in self.networks):
            allowed = ", ".join(str(n) for n in self.networks) or "nothing"
            raise ScopeError(
                f"{addr} is outside the allowed scope ({allowed}). If you are authorised to test "
                "it, add it to CYBERDECK_SCOPE_EXTRA in your .env (see .env.example)."
            )
        return str(addr)


def _address_candidates(token: str) -> Iterator[str]:
    text = token.strip()
    if "://" in text:
        host = urlsplit(text).hostname
        if host:
            yield host
        return
    yield text
    if "=" in text:
        yield text.rsplit("=", 1)[1]


def check_argv_scope(argv: Sequence[str], scope: Scope) -> None:
    """Refuse a command line that mentions any IP or CIDR outside the scope.

    Hostnames are not resolved here; they are only reachable through /etc/hosts entries that
    point at in-scope IPs (Cyberdeck only ever maps names to the scope-checked box IP).
    """
    for token in argv:
        for candidate in _address_candidates(token):
            try:
                addr = ip_address(candidate)
            except ValueError:
                pass
            else:
                if not scope.contains(str(addr)):
                    raise ScopeError(f"command mentions {addr}, which is outside the allowed scope")
                continue
            if "/" not in candidate:
                continue
            try:
                net = ip_network(candidate, strict=False)
            except ValueError:
                continue
            inside = any(
                net.version == allowed.version and net.subnet_of(allowed)  # type: ignore[arg-type]
                for allowed in scope.networks
            )
            if not inside:
                raise ScopeError(f"command mentions {net}, which is outside the allowed scope")
