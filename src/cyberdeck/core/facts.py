"""Box facts derived from findings: what planners, providers and rules need to know about a
box. Pure functions over findings; the service layer reads them from the box's DB."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cyberdeck.core.models import Finding, FindingType, Hostname, OsGuess, Service, Software


@dataclass(frozen=True)
class BoxFacts:
    services: list[Service]
    hostnames: list[Hostname]
    software: list[Software]
    os_families: list[str]

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> BoxFacts:
        items = list(findings)
        return cls(
            services=sorted(
                (f.as_(Service) for f in items if f.type is FindingType.SERVICE),
                key=lambda s: (s.proto, s.port),
            ),
            hostnames=[f.as_(Hostname) for f in items if f.type is FindingType.HOSTNAME],
            software=[f.as_(Software) for f in items if f.type is FindingType.SOFTWARE],
            os_families=[f.as_(OsGuess).family for f in items if f.type is FindingType.OS],
        )

    @property
    def web_services(self) -> list[Service]:
        """Open TCP services that are websites (``kind: web``; WinRM is not, even though nmap
        calls it http), port 80/443 first."""
        from cyberdeck.core.classify import WEB, service_kind

        web = [
            s
            for s in self.services
            if s.proto == "tcp" and s.state == "open" and service_kind(s) == WEB
        ]
        web.sort(key=lambda s: (s.port not in (80, 443), s.port))
        return web


def best_hostname(facts: BoxFacts) -> str | None:
    hosts = [h for h in facts.hostnames if h.kind == "host"]
    if not hosts:
        return None
    # Prefer short names (box.htb over dev.box.htb), then the first found.
    return min(hosts, key=lambda h: h.fqdn.count(".")).fqdn


def best_domain(facts: BoxFacts) -> str | None:
    domains = [h.fqdn for h in facts.hostnames if h.kind == "domain"]
    if domains:
        return min(domains, key=lambda d: d.count("."))
    host = best_hostname(facts)
    if host is None:
        return None
    return host if host.count(".") == 1 else host.split(".", 1)[1]


def web_urls(facts: BoxFacts, ip: str, host: str | None) -> list[str]:
    """Base URLs of the web services (port 80/443 first), by ``host`` when given."""
    return [u for u in (s.url(host or ip) for s in facts.web_services) if u]


def matches_when(when: dict[str, list[str]], facts: BoxFacts) -> bool:
    """A manifest option's ``when:`` (software/service/os, case-insensitive substring)."""
    haystacks = {
        "software": [s.name for s in facts.software]
        + [s.product for s in facts.services if s.product],
        "service": [s.name for s in facts.services if s.name],
        "os": facts.os_families,
    }
    for key, needles in when.items():
        names = [n.lower() for n in haystacks.get(key, [])]
        if any(needle.lower() in name for needle in needles for name in names):
            return True
    return False
