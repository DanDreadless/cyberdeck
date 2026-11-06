"""Service classification (plugins/services.yaml): rules match what a port is, not nmap's name."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cyberdeck.core import services
from cyberdeck.core.classify import kind_table, service_kind
from cyberdeck.core.config import Settings
from cyberdeck.core.models import Finding, Hostname, Service
from cyberdeck.core.tools import registry

from .conftest import make_ws

IP = "10.129.1.13"
HTTPAPI = "Microsoft HTTPAPI httpd"


@pytest.fixture(autouse=True)
def fresh() -> None:
    registry(reload=True)


@pytest.mark.parametrize(
    ("svc", "kind"),
    [
        (Service(port=5985, name="http", product=HTTPAPI, version="2.0"), "winrm"),
        (Service(port=5986, name="https", product=HTTPAPI, tunnel="ssl"), "winrm"),
        (Service(port=8443, name="http", product=HTTPAPI, version="2.0"), "web"),
        (Service(port=80, name="http", product="nginx"), "web"),
        (Service(port=8080, name="http-proxy"), "web"),
        (Service(port=445, name="microsoft-ds"), "smb"),
        (Service(port=135, name="msrpc"), "rpc"),
        (Service(port=3389, name="ms-wbt-server"), "rdp"),
        (Service(port=22, name="ssh"), "ssh"),
        (Service(port=9091, name="xmltec-xmlmail"), "xmltec-xmlmail"),  # unknown: nmap's name
        (Service(port=1234), "unknown"),
    ],
)
def test_builtin_kinds(svc: Service, kind: str) -> None:
    assert service_kind(svc) == kind
    assert kind_table().errors == []


def test_user_kinds_come_first_and_errors_are_reported(tmp_path: Path) -> None:
    user = tmp_path / "xdg" / "cyberdeck" / "services.yaml"
    user.parent.mkdir(parents=True)
    user.write_text(
        yaml.safe_dump([{"kind": "my-admin", "ports": [8443]}, {"kind": "broken"}]),
        encoding="utf-8",
    )
    assert service_kind(Service(port=8443, name="http", product=HTTPAPI)) == "my-admin"
    errors = [msg for _, msg in kind_table().errors]
    assert errors and "needs ports, names, products or tunnel" in errors[0]
    assert any("services.yaml" in str(p) for p, _ in services.tool_load_errors())


def test_touch_like_box_gets_web_steps_only_for_the_real_site(settings: Settings) -> None:
    """A Windows box with 135, 3389, 5985 (WinRM) and 8443 (a site): nmap calls 5985 and 8443
    both "http", but only 8443 is a website."""
    ws = make_ws(settings, "touch", IP)
    with ws.store() as store:
        for svc in (
            Service(port=135, name="msrpc", product="Microsoft Windows RPC"),
            Service(port=3389, name="ms-wbt-server", product="Microsoft Terminal Service"),
            Service(port=5985, name="http", product=HTTPAPI, version="2.0"),
            Service(port=8443, name="http", product=HTTPAPI, version="2.0"),
        ):
            store.upsert(Finding.of(svc, source="test"))
        store.upsert(Finding.of(Hostname(fqdn="touch.htb", ip=IP), source="test"))
    settings.hosts_file.write_text(f"{IP} touch.htb\n", encoding="utf-8")

    found = services.list_suggestions(ws)
    web_urls = {s.values.get("url") for s in found if s.rule_id.startswith("web.")}
    assert web_urls and all(":8443/" in (u or "") for u in web_urls)
    assert not any("5985" in s.title for s in found)

    plan = services.plan_tool(ws, "whatweb", settings=settings)
    assert plan.values["url"] == "http://touch.htb:8443/"  # not WinRM's 5985
