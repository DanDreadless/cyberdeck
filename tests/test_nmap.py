from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.models import FindingType, Hostname, OsGuess, Service, Software
from cyberdeck.ingest.nmap import (
    discover,
    domain_from_extrainfo,
    hostnames_from_script,
    import_path,
    parse_gnmap,
    parse_xml,
    split_product_version,
)
from cyberdeck.store.db import Store

from .conftest import FIXTURES, make_ws


def _payloads(store: Store, type_: FindingType, cls: type) -> list:  # type: ignore[type-arg]
    return [f.as_(cls) for f in store.findings(type_)]


def _hostnames(store: Store) -> dict[str, str]:
    return {h.fqdn: h.kind for h in _payloads(store, FindingType.HOSTNAME, Hostname)}


# --- unit: extraction helpers ---------------------------------------------------------------


def test_redirect_hostname() -> None:
    hits = hostnames_from_script("http-title", "Did not follow redirect to http://Lantern.htb/")
    assert hits == [("lantern.htb", "host", 0.95)]
    ip_redirect = "Did not follow redirect to http://10.129.1.1/"
    assert hostnames_from_script("http-title", ip_redirect) == []


def test_ssl_cert_ignores_issuer_and_handles_wildcards() -> None:
    out = (
        "Subject: commonName=portal.nimbus.htb/organizationName=X\n"
        "Subject Alternative Name: DNS:portal.nimbus.htb, DNS:*.nimbus.htb\n"
        "Issuer: commonName=ca.example.com"
    )
    assert hostnames_from_script("ssl-cert", out) == [
        ("portal.nimbus.htb", "host", 0.9),
        ("nimbus.htb", "domain", 0.9),
    ]


def test_ldap_rootdse() -> None:
    out = "  dnsHostName: DC01.corp.htb\n  defaultNamingContext: DC=corp,DC=htb"
    assert hostnames_from_script("ldap-rootdse", out) == [
        ("dc01.corp.htb", "host", 0.9),
        ("corp.htb", "domain", 0.9),
    ]


@pytest.mark.parametrize(
    ("extrainfo", "expected"),
    [
        ("Domain: ledger.htb0., Site: Default-First-Site-Name", "ledger.htb"),
        ("Domain: corp.local, Site: X", "corp.local"),
        ("workgroup: WORKGROUP", None),
        (None, None),
    ],
)
def test_domain_from_extrainfo(extrainfo: str | None, expected: str | None) -> None:
    assert domain_from_extrainfo(extrainfo) == expected


def test_split_product_version() -> None:
    assert split_product_version("Apache httpd 2.4.41") == ("Apache httpd", "2.4.41")
    assert split_product_version("Microsoft Windows RPC") == ("Microsoft Windows RPC", None)
    assert split_product_version("WordPress 6.4.2") == ("WordPress", "6.4.2")


# --- parsing fixtures -----------------------------------------------------------------------


def test_parse_xml_lantern() -> None:
    scan = parse_xml(FIXTURES / "lantern" / "lantern.xml")
    assert scan.kind == "xml" and scan.args and "-sC -sV" in scan.args
    (host,) = scan.hosts
    services_ = [f.as_(Service) for f in host.findings if f.type is FindingType.SERVICE]
    assert [s.port for s in services_] == [22, 80, 9091]
    ssh = services_[0]
    assert (ssh.product, ssh.version) == ("OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10")
    assert "ssh-hostkey" in ssh.scripts


def test_parse_gnmap() -> None:
    scan = parse_gnmap(FIXTURES / "gnmap-only" / "quill.gnmap")
    (host,) = scan.hosts
    by_port = {
        f.as_(Service).port: f.as_(Service) for f in host.findings if f.type is FindingType.SERVICE
    }
    assert sorted(by_port) == [22, 443, 8000]  # filtered 3306 skipped
    assert by_port[443].tunnel == "ssl" and by_port[443].name == "http"
    assert by_port[443].url("quill.htb") == "https://quill.htb/"
    assert (by_port[8000].product, by_port[8000].version, by_port[8000].extrainfo) == (
        "Werkzeug httpd",
        "3.0.1",
        "Python 3.12.3",
    )
    names = [f.as_(Hostname).fqdn for f in host.findings if f.type is FindingType.HOSTNAME]
    assert names == ["quill.htb"]


def test_discover_prefers_xml(tmp_path: Path) -> None:
    files = [p.name for p in discover(FIXTURES / "lantern")]
    assert files == ["lantern-allports.xml", "lantern.xml"]  # .gnmap twin and .nmap skipped
    hidden = tmp_path / ".cache"
    hidden.mkdir()
    shutil.copy(FIXTURES / "drift" / "drift.xml", hidden / "x.xml")
    assert discover(tmp_path) == []


# --- import into a workspace ----------------------------------------------------------------


def test_import_two_stage_merge(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", "10.129.231.15")
    shutil.copytree(FIXTURES / "lantern", ws.nmap_dir, dirs_exist_ok=True)
    report = services.import_nmap(ws)
    assert len(report.imported) == 2 and not report.skipped
    with ws.store() as store:
        svcs = {s.port: s for s in _payloads(store, FindingType.SERVICE, Service)}
        assert sorted(svcs) == [22, 80, 9091]
        assert svcs[80].product == "nginx"  # probed stage-2 data filled in the stage-1 stub
        svc80 = store.get(FindingType.SERVICE, "tcp/80")
        assert svc80 is not None and svc80.confidence == 1.0
        assert svc80.sources == ["nmap:lantern-allports.xml", "nmap:lantern.xml"]
        assert _hostnames(store) == {"lantern.htb": "host"}
        names = {s.name for s in _payloads(store, FindingType.SOFTWARE, Software)}
        assert names == {"OpenSSH", "nginx"}

    again = services.import_nmap(ws)
    assert not again.imported and len(again.skipped) == 2  # idempotent
    forced = services.import_nmap(ws, force=True)
    assert len(forced.imported) == 2 and not forced.created


def test_import_windows_dc(settings: Settings) -> None:
    ws = make_ws(settings, "ledger", "10.129.40.20")
    services.import_nmap(ws, FIXTURES / "ledger")
    summary = services.target_summary(ws)
    assert len(summary.services) == 12
    assert summary.best_os == "Windows"
    assert {h.fqdn: h.kind for h in summary.hostnames} == {
        "dc01.ledger.htb": "host",
        "ledger.htb": "domain",
    }
    assert services.hosts_file_line(ws.meta.ip, summary.hostnames) == (
        "10.129.40.20 dc01.ledger.htb ledger.htb"
    )
    ldaps = next(s for s in summary.services if s.port == 636)
    assert ldaps.tunnel == "ssl"


def test_import_ftp_no_hostnames(settings: Settings) -> None:
    ws = make_ws(settings, "drift", "10.129.50.5")
    services.import_nmap(ws, FIXTURES / "drift" / "drift.xml")
    summary = services.target_summary(ws)
    assert [s.port for s in summary.services] == [21, 22, 80]  # filtered 8080 skipped
    assert summary.hostnames == []
    assert "ftp-anon" in summary.services[0].scripts
    assert {"linux", "unix"} == {o.family.lower() for o, _ in summary.os_guesses}


def test_import_filters_other_hosts(settings: Settings) -> None:
    ws = make_ws(settings, "vault", "10.129.60.7")
    report = services.import_nmap(ws, FIXTURES / "vault")
    assert report.other_hosts == {"10.129.60.8"}  # down host 10.129.60.9 not even reported
    summary = services.target_summary(ws)
    assert [s.port for s in summary.services] == [139, 445]
    assert {h.fqdn for h in summary.hostnames} == {"files.vault.htb", "vault.htb"}
    assert summary.best_os == "Linux"  # "Windows 6.1 (Samba 4.6.2)" is Samba


def test_import_vhosts_wordpress_os(settings: Settings) -> None:
    ws = make_ws(settings, "nimbus", "10.129.70.9")
    services.import_nmap(ws, FIXTURES / "nimbus")
    with ws.store() as store:
        assert _hostnames(store) == {
            "nimbus.htb": "host",  # redirect (0.95) beats the wildcard's "domain" (0.9)
            "portal.nimbus.htb": "host",
            "dev.nimbus.htb": "host",
        }
        sw = {(s.name, s.version) for s in _payloads(store, FindingType.SOFTWARE, Software)}
        assert ("WordPress", "6.4.2") in sw
        os_ = store.get(FindingType.OS, "linux")
        assert os_ is not None and os_.as_(OsGuess).name == "Linux 5.0 - 5.14"


def test_truncated_xml_falls_back_to_gnmap(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    xml = (FIXTURES / "lantern" / "lantern.xml").read_text()
    (scan_dir / "lantern.xml").write_text(xml[: len(xml) // 2])  # interrupted scan
    shutil.copy(FIXTURES / "lantern" / "lantern.gnmap", scan_dir / "lantern.gnmap")
    with Store(tmp_path / "t.db") as store:
        report = import_path(store, scan_dir, "10.129.231.15")
        assert [p.name for p in report.imported] == ["lantern.gnmap"]
        assert report.notes and "used lantern.gnmap" in report.notes[0]
        assert len(store.findings(FindingType.SERVICE)) == 3


def test_import_missing_path(tmp_path: Path) -> None:
    with Store(tmp_path / "t.db") as store, pytest.raises(FileNotFoundError):
        import_path(store, tmp_path / "nope", "10.129.1.1")
