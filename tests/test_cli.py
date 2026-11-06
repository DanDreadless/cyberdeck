from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import services
from cyberdeck.core.userconfig import load_user_config
from cyberdeck.util.vpn import Tunnel, VpnStatus

from .conftest import FIXTURES

runner = CliRunner()
FAKE_NMAP = Path(__file__).parent / "fake_nmap.py"
IP = "10.129.231.15"


@pytest.fixture(autouse=True)
def wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "console", Console(width=200))
    monkeypatch.setattr(cli, "err_console", Console(width=200, stderr=True))


@pytest.fixture
def vpn_up(monkeypatch: pytest.MonkeyPatch) -> None:
    def status(settings: object, ip: str) -> VpnStatus:
        return VpnStatus(ip, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0")

    monkeypatch.setattr(services, "vpn_check", status)


@pytest.fixture
def fake_nmap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(cli, "have_binary", lambda name: True)
    monkeypatch.setattr(cli, "is_root", lambda: False)


def test_version_and_banner() -> None:
    assert "cyberdeck 0.0.1" in runner.invoke(cli.app, ["--version"]).output
    assert "A CTF Companion Tool" in runner.invoke(cli.app, []).output


def test_new_no_scan_import_show_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = runner.invoke(cli.app, ["new", "Lantern", "--ip", IP, "--no-scan"])
    assert result.exit_code == 0, result.output
    ws_path = tmp_path / "htb" / "lantern"
    assert f"-oA nmap/lantern-allports {IP}" in result.output

    shutil.copytree(FIXTURES / "lantern", ws_path / "nmap", dirs_exist_ok=True)
    monkeypatch.chdir(ws_path)  # no --target: found from the current directory
    result = runner.invoke(cli.app, ["import"])
    assert result.exit_code == 0, result.output
    assert "New hostnames: lantern.htb" in result.output and "cyberdeck hosts add" in result.output
    assert "Suggested next steps" in result.output and "Add lantern.htb" in result.output

    result = runner.invoke(cli.app, ["show"])
    for text in ("OpenSSH 8.9p1", "nginx 1.18.0", "lantern.htb", "OS: Linux"):
        assert text in result.output
    assert "Lantern" in runner.invoke(cli.app, ["list"]).output


def test_wizard_remembers_root_and_scans(tmp_path: Path, vpn_up: None, fake_nmap: None) -> None:
    boxes = tmp_path / "Documents" / "htb"
    answers = "\n".join(["Lantern", IP, str(boxes), "y", "y"]) + "\n"
    answers += "\n\n"  # Enter = run, in the Run dialog of each stage
    result = runner.invoke(cli.app, ["new"], input=answers)
    assert result.exit_code == 0, result.output
    assert (boxes / "lantern" / "nmap" / "lantern.xml").is_file()
    assert "VPN:" in result.output and "LHOST: 10.10.14.7" in result.output
    assert "Open TCP ports: 22,80,9091" in result.output
    assert "-p22,80,9091" in result.output  # stage 2 dialog was pre-filled from stage 1
    assert "lantern.htb" in result.output
    # the folder choice was saved to config.yaml (env vars, set in tests, still win over it)
    assert load_user_config().workspace_root == str(boxes)
    assert "Lantern" in runner.invoke(cli.app, ["list", "--root", str(boxes)]).output


def test_scan_yes_with_options_and_jobs(
    tmp_path: Path, vpn_up: None, fake_nmap: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.invoke(cli.app, ["new", "lantern", "--ip", IP, "--no-scan"])
    monkeypatch.chdir(tmp_path / "htb" / "lantern")
    result = runner.invoke(
        cli.app, ["scan", "--yes", "--opt", "min_rate=1000", "--", "--max-rtt-timeout", "500ms"]
    )
    assert result.exit_code == 0, result.output
    assert "--min-rate 1000" in result.output and "--max-rtt-timeout 500ms" in result.output

    jobs = runner.invoke(cli.app, ["jobs"]).output
    assert "nmap-allports" in jobs and "nmap-services" in jobs and "done" in jobs
    detail = runner.invoke(cli.app, ["job", "1"]).output
    assert "--min-rate 1000" in detail and "Discovered open port" in detail
    assert "fake nmap" in runner.invoke(cli.app, ["job", "1", "--err"]).output


def test_run_dialog_edit_and_skip(
    tmp_path: Path, vpn_up: None, fake_nmap: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.invoke(cli.app, ["new", "lantern", "--ip", IP, "--no-scan"])
    monkeypatch.chdir(tmp_path / "htb" / "lantern")
    # option 4 = Min rate; set it, save as box default, then skip (q)
    result = runner.invoke(cli.app, ["run", "nmap-allports"], input="4\n1500\nb\nq\n")
    assert result.exit_code == 0, result.output
    assert "--min-rate 1500" in result.output and "Saved for this box" in result.output
    assert "Skipped" in result.output
    assert "min_rate: 1500" in (tmp_path / "htb" / "lantern" / "target.yaml").read_text()

    udp = runner.invoke(cli.app, ["run", "nmap-udp", "--yes"])
    assert udp.exit_code == 1 and "needs root" in udp.output


def test_vpn_down_blocks_unattended_scan(
    tmp_path: Path, fake_nmap: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "htb"
    runner.invoke(cli.app, ["new", "lantern", "--ip", IP, "--no-scan"])
    (root / "machines_us-1.ovpn").write_text("client\n")
    from cyberdeck.util import vpn

    monkeypatch.setattr(
        services,
        "vpn_check",
        lambda settings, ip: VpnStatus(
            ip, True, [], route_dev="eth0", configs=vpn.find_configs(root, None)
        ),
    )
    result = runner.invoke(cli.app, ["scan", "--yes", "-t", "lantern"])
    assert result.exit_code == 1
    assert "HTB VPN tunnel is not up" in result.output
    assert "openvpn --config" in result.output and "machines_us-1.ovpn" in result.output


def test_errors_exit_nonzero() -> None:
    assert runner.invoke(cli.app, ["new", "google", "--ip", "8.8.8.8", "--no-scan"]).exit_code == 1
    assert runner.invoke(cli.app, ["show"]).exit_code == 1
    assert runner.invoke(cli.app, ["show", "--target", "missing"]).exit_code == 1
    assert runner.invoke(cli.app, ["run", "nikto"]).exit_code == 1
    assert "nmap-allports" in runner.invoke(cli.app, ["run", "list"]).output


def test_vpn_down_offers_systemd_service(
    tmp_path: Path, fake_nmap: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.invoke(cli.app, ["new", "lantern", "--ip", IP, "--no-scan"])
    monkeypatch.setattr(
        services,
        "vpn_check",
        lambda settings, ip: VpnStatus(ip, True, [], services=["openvpn-client@htb.service"]),
    )
    result = runner.invoke(cli.app, ["scan", "--yes", "-t", "lantern"])
    assert result.exit_code == 1
    assert "sudo systemctl start openvpn-client@htb.service" in result.output
