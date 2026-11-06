"""Import nmap results into a target's store.

XML (``-oX`` / ``-oA``) is preferred. Grepable output (``.gnmap``) is used when no XML sibling
exists, or when the XML is truncated (scan interrupted). Normal output (``.nmap``) is ignored.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET  # noqa: S405 - see parse_xml
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from cyberdeck.core.models import (
    Finding,
    HostKind,
    Hostname,
    OsGuess,
    Payload,
    Service,
    Software,
    normalise_fqdn,
)
from cyberdeck.store.db import Store


class NmapParseError(ValueError):
    pass


@dataclass
class ParsedHost:
    ip: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class ParsedScan:
    path: Path
    kind: str  # "xml" | "gnmap"
    args: str | None
    hosts: list[ParsedHost]


@dataclass
class ImportReport:
    imported: list[Path] = field(default_factory=list)
    skipped: list[tuple[Path, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created: list[Finding] = field(default_factory=list)
    updated: list[Finding] = field(default_factory=list)
    other_hosts: set[str] = field(default_factory=set)


# --- hostname extraction --------------------------------------------------------------------

HostHit = tuple[str, HostKind, float]

_REDIRECT_RE = re.compile(r"Did not follow redirect to (\S+)", re.IGNORECASE)
_CN_RE = re.compile(r"commonName=([^\s/,]+)")
_SAN_RE = re.compile(r"DNS:([^\s,]+)")
_DC_RE = re.compile(r"DC=([^,]+)", re.IGNORECASE)
_NTLM_SCRIPTS = frozenset(
    {"rdp-ntlm-info", "http-ntlm-info", "smtp-ntlm-info", "imap-ntlm-info", "ms-sql-ntlm-info"}
)


def _kv(output: str, key: str) -> str | None:
    match = re.search(rf"^\s*{re.escape(key)}\s*:\s*(\S+)\s*$", output, re.MULTILINE)
    return match.group(1) if match else None


def _hit(found: list[HostHit], raw: str | None, kind: HostKind, confidence: float) -> None:
    if not raw:
        return
    if raw.startswith("*."):
        raw, kind = raw[2:], "domain"
    name = normalise_fqdn(raw)
    if name and all(existing[0] != name for existing in found):
        found.append((name, kind, confidence))


def hostnames_from_script(script_id: str, output: str) -> list[HostHit]:
    """Extract hostnames/domains from one NSE script's output."""
    found: list[HostHit] = []
    if script_id == "http-title":
        for match in _REDIRECT_RE.finditer(output):
            _hit(found, urlsplit(match.group(1)).hostname, "host", 0.95)
    elif script_id == "ssl-cert":
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Subject Alternative Name:"):
                for match in _SAN_RE.finditer(stripped):
                    _hit(found, match.group(1), "host", 0.9)
            elif stripped.startswith("Subject:"):
                for match in _CN_RE.finditer(stripped):
                    _hit(found, match.group(1), "host", 0.9)
    elif script_id == "smb-os-discovery":
        _hit(found, _kv(output, "FQDN"), "host", 0.9)
        _hit(found, _kv(output, "Domain name"), "domain", 0.9)
        _hit(found, _kv(output, "Forest name"), "domain", 0.85)
    elif script_id in _NTLM_SCRIPTS:
        _hit(found, _kv(output, "DNS_Computer_Name"), "host", 0.9)
        _hit(found, _kv(output, "DNS_Domain_Name"), "domain", 0.9)
        _hit(found, _kv(output, "DNS_Tree_Name"), "domain", 0.85)
    elif script_id == "ldap-rootdse":
        _hit(found, _kv(output, "dnsHostName"), "host", 0.9)
        for key in ("defaultNamingContext", "rootDomainNamingContext"):
            value = _kv(output, key)
            if value:
                _hit(found, ".".join(_DC_RE.findall(value)), "domain", 0.9)
    return found


def domain_from_extrainfo(extrainfo: str | None) -> str | None:
    """AD LDAP banners look like ``Domain: corp.htb0., Site: ...``. The ``0.`` is an nmap
    quirk and is stripped."""
    if not extrainfo:
        return None
    match = re.search(r"Domain: ([^,)\s]+)", extrainfo)
    if not match:
        return None
    domain = match.group(1)
    if domain.endswith("0."):
        domain = domain[:-2]
    return normalise_fqdn(domain)


def _os_from_smb(output: str) -> tuple[str, str] | None:
    match = re.search(r"^\s*OS:\s*(.+?)\s*$", output, re.MULTILINE)
    if not match:
        return None
    text = match.group(1)
    lowered = text.lower()
    if "samba" in lowered or "unix" in lowered:
        return "Linux", text
    if "windows" in lowered:
        return "Windows", text
    return None


def split_product_version(text: str) -> tuple[str, str | None]:
    """``"Apache httpd 2.4.41"`` -> ``("Apache httpd", "2.4.41")``."""
    tokens = text.split()
    for index, token in enumerate(tokens):
        if index > 0 and token[0].isdigit():
            return " ".join(tokens[:index]), " ".join(tokens[index:])
    return text.strip(), None


def _split_banner(text: str) -> tuple[str | None, str | None, str | None]:
    """gnmap version field -> (product, version, extrainfo)."""
    text = text.strip()
    if not text:
        return None, None, None
    match = re.match(r"^(?P<main>.*?)(?: \((?P<extra>[^()]*)\))?$", text)
    main = match.group("main") if match else text
    extra = match.group("extra") if match else None
    product, version = split_product_version(main) if main else (None, None)
    return product or None, version, extra


# --- XML ------------------------------------------------------------------------------------


def _service_confidence(method: str | None, conf: str | None) -> float:
    default = 0.9 if method == "probed" else 0.3
    value = int(conf) / 10 if conf and conf.isdigit() else default
    if method == "table":
        value = min(value, 0.3)
    return max(0.1, min(1.0, value))


def _host_ip(host_el: ET.Element) -> str | None:
    for addr in host_el.iterfind("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr")
    return None


def _service_findings(
    svc: Service, ip: str, confidence: float, add: Callable[[Payload, float], None]
) -> None:
    where = svc.natural_key()
    add(svc, confidence)
    if svc.product:
        cpe = next((c for c in svc.cpe if c.startswith("cpe:/a:")), None)
        add(Software(name=svc.product, version=svc.version, cpe=cpe, where=where), confidence)
    if svc.ostype:
        add(OsGuess(family=svc.ostype), 0.6)
    domain = domain_from_extrainfo(svc.extrainfo)
    if domain:
        add(Hostname(fqdn=domain, ip=ip, kind="domain", origins=[f"nmap:banner@{where}"]), 0.85)
    for script_id, output in svc.scripts.items():
        for name, kind, conf in hostnames_from_script(script_id, output):
            add(Hostname(fqdn=name, ip=ip, kind=kind, origins=[f"nmap:{script_id}@{where}"]), conf)
    generator = svc.scripts.get("http-generator")
    if generator and generator.strip():
        name, version = split_product_version(generator.strip())
        add(Software(name=name, version=version, where=where), 0.8)


def _parse_host(host_el: ET.Element, ip: str, source: str) -> ParsedHost:
    parsed = ParsedHost(ip)

    def add(payload: Payload, confidence: float) -> None:
        parsed.findings.append(Finding.of(payload, source=source, confidence=confidence))

    for hn in host_el.iterfind("hostnames/hostname"):
        name = normalise_fqdn(hn.get("name", ""))
        if name:
            kind = hn.get("type", "?")
            origin = f"nmap:hostname-{kind}"
            add(Hostname(fqdn=name, ip=ip, origins=[origin]), 0.9 if kind == "user" else 0.5)

    for port_el in host_el.iterfind("ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc_el = port_el.find("service")
        attrs = dict(svc_el.attrib) if svc_el is not None else {}
        cpes = [c.text for c in svc_el.iterfind("cpe") if c.text] if svc_el is not None else []
        svc = Service(
            proto=port_el.get("protocol", "tcp"),
            port=int(port_el.get("portid", "0")),
            reason=state_el.get("reason"),
            name=attrs.get("name"),
            product=attrs.get("product"),
            version=attrs.get("version"),
            extrainfo=attrs.get("extrainfo"),
            ostype=attrs.get("ostype"),
            tunnel=attrs.get("tunnel"),
            cpe=cpes,
            scripts={s.get("id", ""): s.get("output", "") for s in port_el.iterfind("script")},
        )
        confidence = _service_confidence(attrs.get("method"), attrs.get("conf"))
        _service_findings(svc, ip, confidence, add)

    for script in host_el.iterfind("hostscript/script"):
        script_id, output = script.get("id", ""), script.get("output", "")
        for name, kind, conf in hostnames_from_script(script_id, output):
            add(Hostname(fqdn=name, ip=ip, kind=kind, origins=[f"nmap:{script_id}"]), conf)
        if script_id == "smb-os-discovery":
            smb_os = _os_from_smb(output)
            if smb_os:
                add(OsGuess(family=smb_os[0], name=smb_os[1]), 0.7)

    matches = list(host_el.iterfind("os/osmatch"))
    if matches:
        best = max(matches, key=lambda m: int(m.get("accuracy", "0")))
        osclass = best.find("osclass")
        os_name = best.get("name", "")
        family = (osclass.get("osfamily") if osclass is not None else None) or os_name.split()[0]
        accuracy = int(best.get("accuracy", "0"))
        add(OsGuess(family=family, name=os_name or None, accuracy=accuracy), accuracy / 100)
    return parsed


def parse_xml(path: Path) -> ParsedScan:
    try:
        # nmap output we (or the user) produced. Python 3.11+ bundles expat >= 2.4.1, which
        # blocks entity-expansion ("billion laughs") attacks.
        tree = ET.parse(path)  # noqa: S314
    except ET.ParseError as exc:
        raise NmapParseError(f"{path.name}: not valid XML ({exc})") from exc
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise NmapParseError(f"{path.name}: not an nmap XML file")
    source = f"nmap:{path.name}"
    hosts: list[ParsedHost] = []
    for host_el in root.iter("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") == "down":
            continue
        ip = _host_ip(host_el)
        if ip:
            hosts.append(_parse_host(host_el, ip, source))
    return ParsedScan(path, "xml", root.get("args"), hosts)


# --- gnmap ----------------------------------------------------------------------------------

_GN_HOST_RE = re.compile(r"^Host: (\S+) \(([^)]*)\)\t(.*)$")
_GN_PORT_RE = re.compile(r"(\d+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/")


def parse_gnmap(path: Path) -> ParsedScan:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "# Nmap" not in text and "Host: " not in text:
        raise NmapParseError(f"{path.name}: not an nmap grepable file")
    source = f"nmap:{path.name}"
    args: str | None = None
    hosts: dict[str, ParsedHost] = {}
    seen_names: set[tuple[str, str]] = set()
    for line in text.splitlines():
        if line.startswith("# Nmap") and " as: " in line:
            args = line.split(" as: ", 1)[1].strip()
            continue
        match = _GN_HOST_RE.match(line)
        if not match:
            continue
        ip, name, rest = match.groups()
        parsed = hosts.setdefault(ip, ParsedHost(ip))

        def add(payload: Payload, confidence: float, parsed: ParsedHost = parsed) -> None:
            parsed.findings.append(Finding.of(payload, source=source, confidence=confidence))

        fqdn = normalise_fqdn(name)
        if fqdn and (ip, fqdn) not in seen_names:  # each host appears on several lines
            seen_names.add((ip, fqdn))
            add(Hostname(fqdn=fqdn, ip=ip, origins=["nmap:gnmap-hostname"]), 0.5)
        for part in rest.split("\t"):
            if not part.startswith("Ports: "):
                continue
            for port_match in _GN_PORT_RE.finditer(part[len("Ports: ") :]):
                port, state, proto, _owner, svc_name, _rpc, banner = port_match.groups()
                if state != "open":
                    continue
                tunnel: str | None = None
                service_name = svc_name.rstrip("?") or None
                if service_name and "|" in service_name:
                    tunnel, service_name = service_name.split("|", 1)
                product, version, extra = _split_banner(banner.replace("|", "/"))
                svc = Service(
                    proto=proto or "tcp",
                    port=int(port),
                    name=service_name,
                    product=product,
                    version=version,
                    extrainfo=extra,
                    tunnel=tunnel,
                )
                _service_findings(svc, ip, 0.6 if product else 0.3, add)
    return ParsedScan(path, "gnmap", args, list(hosts.values()))


# --- discovery and import -------------------------------------------------------------------


def _looks_like_nmap_xml(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"<nmaprun" in fh.read(4096)
    except OSError:
        return False


def discover(path: Path) -> list[Path]:
    """nmap result files under ``path``; XML wins over a ``.gnmap`` with the same stem."""
    if path.is_file():
        return [path]
    files = sorted(
        p
        for p in path.rglob("*")
        if p.is_file()
        and p.suffix in (".xml", ".gnmap")
        and not any(part.startswith(".") for part in p.relative_to(path).parts)
    )
    xml_stems = {p.with_suffix("") for p in files if p.suffix == ".xml" and _looks_like_nmap_xml(p)}
    selected: list[Path] = []
    for p in files:
        if p.suffix == ".xml":
            if p.with_suffix("") in xml_stems:
                selected.append(p)
        elif p.with_suffix("") not in xml_stems:
            selected.append(p)
    return selected


def parse_file(path: Path) -> ParsedScan:
    return parse_gnmap(path) if path.suffix == ".gnmap" else parse_xml(path)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _same_ip(a: str, b: str) -> bool:
    try:
        return ip_address(a) == ip_address(b)
    except ValueError:
        return a == b


def import_path(store: Store, path: Path, target_ip: str, *, force: bool = False) -> ImportReport:
    """Import every nmap file under ``path`` for ``target_ip`` into ``store``."""
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")
    report = ImportReport()
    for file in discover(path):
        try:
            scan = parse_file(file)
        except NmapParseError as exc:
            sibling = file.with_suffix(".gnmap")
            if file.suffix != ".xml" or not sibling.is_file():
                report.skipped.append((file, str(exc)))
                continue
            try:
                scan = parse_gnmap(sibling)
            except NmapParseError as exc2:
                report.skipped.append((file, f"{exc}; {exc2}"))
                continue
            report.notes.append(f"{exc}; used {sibling.name} instead")
            file = sibling
        digest = _sha256(file)
        if not force and store.has_import(digest):
            report.skipped.append((file, "already imported (use --force to re-import)"))
            continue
        for host in scan.hosts:
            if not _same_ip(host.ip, target_ip):
                report.other_hosts.add(host.ip)
                continue
            for finding in host.findings:
                result = store.upsert(finding)
                if result.created:
                    report.created.append(result.finding)
                elif result.data_changed:
                    report.updated.append(result.finding)
        store.record_import(file, digest, scan.kind)
        report.imported.append(file)
    return report
