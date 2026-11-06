from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from cyberdeck.core import services
from cyberdeck.core.config import Settings, load_settings
from cyberdeck.core.models import JobStatus
from cyberdeck.core.userconfig import load_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.util.vpn import (
    Tunnel,
    VpnStatus,
    find_configs,
    parse_ip_addr,
    parse_route_dev,
    parse_vpn_services,
    start_command,
)

from .conftest import FIXTURES, make_ws

FAKE_NMAP = Path(__file__).parent / "fake_nmap.py"
IP = "10.129.231.15"


@pytest.fixture
def fake_nmap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fixtures = tmp_path / "fake-fixtures"
    fixtures.mkdir()
    shutil.copy(FIXTURES / "lantern" / "lantern-allports.xml", fixtures / "allports.xml")
    shutil.copy(FIXTURES / "lantern" / "lantern.xml", fixtures / "services.xml")
    monkeypatch.setenv("FAKE_NMAP_FIXTURES", str(fixtures))
    monkeypatch.setattr(
        services,
        "RUNNER_LAUNCHER",
        lambda argv: [sys.executable, str(FAKE_NMAP), *argv[1:]] if argv[0] == "nmap" else argv,
    )
    return fixtures


async def test_two_stage_scan_imports_and_feeds_ports(settings: Settings, fake_nmap: Path) -> None:
    ws = make_ws(settings, "lantern", IP)
    stage2_before = services.plan_tool(ws, "nmap-services")
    assert stage2_before.values["ports"] is None and stage2_before.warnings

    lines: list[str] = []
    stage1 = services.plan_tool(ws, "nmap-allports")
    outcome = await services.execute_plan(
        ws, settings, stage1, on_line=lambda s, ln: lines.append(ln)
    )
    assert outcome.result.ok and outcome.import_report is not None
    assert (ws.nmap_dir / "lantern-allports.xml").is_file()
    assert any("Discovered open port" in ln for ln in lines)
    assert services.open_tcp_ports(ws) == "22,80,9091"

    stage2 = services.plan_tool(ws, "nmap-services")
    assert stage2.values["ports"] == "22,80,9091" and not stage2.warnings
    assert "-p22,80,9091" in stage2.argv()
    outcome2 = await services.execute_plan(ws, settings, stage2)
    assert outcome2.result.ok
    summary = services.target_summary(ws)
    assert {h.fqdn for h in summary.hostnames} == {"lantern.htb"}
    assert [j.tool for j in services.list_jobs(ws)] == ["nmap-allports", "nmap-services"]
    job, cmd, out, err = services.job_files(ws, 2)
    assert job.tool == "nmap-services" and "-sC -sV" in cmd.read_text()  # real argv recorded
    assert "fake nmap" in err.read_text() and "Discovered open port" in out.read_text()


async def test_failed_scan_is_not_imported(
    settings: Settings, fake_nmap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_NMAP_EXIT", "1")
    ws = make_ws(settings, "lantern", IP)
    outcome = await services.execute_plan(ws, settings, services.plan_tool(ws, "nmap-allports"))
    assert outcome.result.job.status is JobStatus.FAILED and outcome.import_report is None


async def test_missing_output_is_reported(settings: Settings, fake_nmap: Path) -> None:
    (fake_nmap / "allports.xml").unlink()
    ws = make_ws(settings, "lantern", IP)
    outcome = await services.execute_plan(ws, settings, services.plan_tool(ws, "nmap-allports"))
    assert outcome.result.ok and outcome.import_report is None and outcome.notes


def test_save_defaults_user_and_box(settings: Settings) -> None:
    ws = make_ws(settings, "lantern", IP)
    plan = services.plan_tool(ws, "nmap-allports", overrides={"min_rate": "1000"})
    services.save_plan_defaults(ws, plan, "user")
    assert load_user_config().tool_defaults["nmap-allports"] == {"min_rate": 1000}
    assert services.plan_tool(ws, "nmap-allports").values["min_rate"] == 1000

    box_plan = services.plan_tool(ws, "nmap-allports", overrides={"min_rate": "500"})
    services.save_plan_defaults(ws, box_plan, "box")
    reopened = Workspace.open(ws.path)
    assert services.plan_tool(reopened, "nmap-allports").values["min_rate"] == 500


def test_workspace_root_default_and_remembered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CYBERDECK_WORKSPACE_ROOT")
    assert load_settings().root == Path("~/Documents/htb").expanduser()
    services.remember_workspace_root(tmp_path / "boxes")
    assert load_settings().root == tmp_path / "boxes"
    monkeypatch.setenv("CYBERDECK_WORKSPACE_ROOT", str(tmp_path / "env"))
    assert load_settings().root == tmp_path / "env"  # env beats config.yaml


# --- VPN ------------------------------------------------------------------------------------

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.152.128/24 brd 192.168.152.255 scope global dynamic eth0
7: tun0    inet 10.10.14.7/23 scope global tun0\\       valid_lft forever preferred_lft forever"""


def test_vpn_parsing() -> None:
    assert parse_ip_addr(IP_ADDR) == [Tunnel("tun0", "10.10.14.7")]
    assert (
        parse_route_dev("10.129.231.15 via 10.10.14.1 dev tun0 src 10.10.14.7 uid 1000") == "tun0"
    )
    assert parse_route_dev("10.129.231.15 via 192.168.152.2 dev eth0 src 192.168.152.128") == "eth0"


def test_vpn_status_properties() -> None:
    up = VpnStatus(IP, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0")
    assert up.applicable and up.up and up.routed_via_tunnel and up.lhost == "10.10.14.7"
    down = VpnStatus(IP, True, [], route_dev="eth0")
    assert not down.up and not down.routed_via_tunnel and down.lhost is None
    assert not VpnStatus("127.0.0.1", True).applicable  # local test targets skip the check


def test_find_configs(tmp_path: Path) -> None:
    (tmp_path / "machines_us-1.ovpn").write_text("client\n")
    assert find_configs(tmp_path, None) == [tmp_path / "machines_us-1.ovpn"]
    assert find_configs(tmp_path, tmp_path / "missing.ovpn") == []
    cmd = start_command(tmp_path / "machines_us-1.ovpn")
    assert cmd[:3] == ["sudo", "-n", "openvpn"] and "--daemon" in cmd


def test_config_preference_and_services(tmp_path: Path) -> None:
    (tmp_path / "competitive_Vault1337.ovpn").write_text("client")
    (tmp_path / "machines_us-1.ovpn").write_text("client")
    assert [p.name for p in find_configs(tmp_path, None)] == [
        "machines_us-1.ovpn",
        "competitive_Vault1337.ovpn",
    ]
    listing = "openvpn-client@htb.service loaded active running OpenVPN tunnel for htb"
    assert parse_vpn_services(listing) == ["openvpn-client@htb.service"]
    assert parse_vpn_services("openvpn.service loaded active exited OpenVPN service") == []
