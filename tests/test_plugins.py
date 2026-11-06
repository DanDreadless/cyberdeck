"""Phase 3: manifests, registry, detection, wordlists, parsers, planning and running tools."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from rich.console import Console
from typer.testing import CliRunner

from cyberdeck import cli
from cyberdeck.core import runner as runner_mod
from cyberdeck.core import services
from cyberdeck.core.config import Settings
from cyberdeck.core.models import Finding, FindingType, Hostname, Software, Url, Vuln
from cyberdeck.core.options import OptionError, RunPlan
from cyberdeck.core.tools import get_tool, registry
from cyberdeck.core.userconfig import load_user_config, save_user_config
from cyberdeck.core.workspace import Workspace
from cyberdeck.plugins import wordlists
from cyberdeck.plugins.detect import ToolStatus, detect, detect_all, tool_help
from cyberdeck.plugins.manifest import (
    PROVIDERS,
    ManifestError,
    builtin_tools_dir,
    load_manifests,
    manifest_to_spec,
)
from cyberdeck.plugins.parsers import ParseContext, ParserError, get_parser, run_parser
from cyberdeck.util.hosts import parse_hosts

from .conftest import FIXTURES, make_ws

TOOL_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
FAKE_TOOL = Path(__file__).parent / "fake_tool.py"
IP = "10.129.231.15"
BUILTIN_WEB = {"whatweb", "feroxbuster", "gobuster-dir", "dirsearch", "ffuf-vhost", "nikto"}


@pytest.fixture(autouse=True)
def fresh_registry() -> None:
    registry(reload=True)


@pytest.fixture
def lantern(settings: Settings) -> Workspace:
    ws = make_ws(settings, "lantern", IP)
    services.import_nmap(ws, FIXTURES / "lantern")
    return ws


def _minimal(**extra: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "id": "demo",
        "name": "Demo",
        "detect": {"binary": "demo"},
        "inputs": {"url": {"from": "web_url"}},
        "options": [{"id": "fast", "flag": "-f", "type": "bool", "default": True}],
        "command": ["demo", "{opt.fast}", "{extra}", "{url}"],
    }
    raw.update(extra)
    return raw


# --- manifests and registry -----------------------------------------------------------------


def test_builtin_manifests_load_cleanly() -> None:
    result = load_manifests(builtin_tools_dir(), Path("/nonexistent"))
    assert result.errors == []
    assert set(result.tools) >= BUILTIN_WEB
    reg = registry()
    assert reg.errors == []
    groups = reg.groups()
    assert [t.id for t in groups["dir-bruteforce"]] == [
        "feroxbuster",
        "gobuster-dir",
        "dirsearch",
        "ffuf-dir",
    ]
    for tool in result.tools.values():
        assert tool.options, f"{tool.id} declares no inputs or options (CLAUDE.md rule 2)"
        assert "{extra}" in tool.command, tool.id
        assert tool.detect and tool.detect.apt, tool.id
        assert tool.source and "/plugins/tools/" in tool.source
        if tool.parser:
            get_parser(tool.parser)  # every referenced parser exists
        if tool.group:
            assert tool.parser, f"{tool.id}: rules suggest groups, so their output must parse"
        for provider in tool.dynamic_defaults.values():
            assert provider in PROVIDERS


def test_tools_folder_layout_templates_and_drafts_are_skipped() -> None:
    from cyberdeck.plugins.manifest import manifest_files

    base = builtin_tools_dir()
    files = manifest_files(base)
    assert all(not part.startswith("_") for f in files for part in f.relative_to(base).parts)
    assert (base / "_template.yaml").is_file() and (base / "_drafts").is_dir()
    tools = registry().tools
    assert tools["strings"].category == "forensics"  # from the folder
    assert tools["whatweb"].source and "/recon/" in tools["whatweb"].source
    assert {o.id: o.type for o in tools["strings"].options}["file"] == "path"
    assert tools["searchsploit"].notes


def test_template_is_a_valid_manifest() -> None:
    raw = yaml.safe_load((builtin_tools_dir() / "_template.yaml").read_text(encoding="utf-8"))
    spec = manifest_to_spec(raw, folder_category="web")
    assert spec.id == "mytool" and spec.category == "web" and spec.safety == "safe"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"command": ["demo", "-u", "{url}/{FUZZ}", "{extra}"]}, "{FUZZ}, which isn't an input"),
        (
            {
                "options": [{"id": "level", "flag": "-l", "type": "int", "default": 1}],
                "command": ["demo", "-l", "{opt.level}", "{url}", "{extra}"],
            },
            "already renders -l",
        ),
        ({"inputs": {"target": {"from": "nowhere"}}}, "unknown from"),
    ],
)
def test_manifest_command_mistakes_are_caught(change: dict[str, Any], message: str) -> None:
    raw = _minimal(**change)
    with pytest.raises(ManifestError, match=re.escape(message)):
        manifest_to_spec(raw)


def test_host_provider_and_file_alias(lantern: Workspace, settings: Settings) -> None:
    raw = _minimal(
        inputs={"target": {"from": "host"}, "file": {"type": "file"}},
        options=[],
        command=["demo", "{target}", "{file}", "{extra}"],
    )
    spec = manifest_to_spec(raw)
    assert {o.id: o.type for o in spec.options}["file"] == "path"
    assert spec.dynamic_defaults == {"target": "host"}


def test_cli_tools_check(tmp_path: Path) -> None:
    good = tmp_path / "web" / "good.yaml"
    good.parent.mkdir()
    good.write_text(yaml.safe_dump(_minimal(id="goodtool")), encoding="utf-8")
    bad = tmp_path / "web" / "bad.yaml"
    bad.write_text(yaml.safe_dump(_minimal(id="badtool", command=["x", "{nope}", "{extra}"])))
    result = cli_runner.invoke(cli.app, ["tools", "check", str(tmp_path)])
    assert result.exit_code == 1
    assert "goodtool" in result.output and "{nope}" in result.output
    assert "1 valid, 1 with errors" in result.output
    assert cli_runner.invoke(cli.app, ["tools", "check", str(good)]).exit_code == 0


def test_manifest_inputs_become_editable_options() -> None:
    spec = manifest_to_spec(_minimal())
    url = spec.option("url")
    assert url.input and url.required and spec.dynamic_defaults == {"url": "web_url"}
    assert spec.binary == "demo"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"colour": "blue"}, "Extra inputs"),
        ({"command": ["demo", "{opt.nope}", "{url}"]}, "no option 'nope'"),
        ({"command": ["demo", "{opt.fast}"]}, "input 'url' is never used"),
        ({"inputs": {"url": {"from": "telepathy"}}}, "unknown from"),
        ({"presets": {"x": {"slow": 1}}}, "unknown option"),
        ({"detect": {}}, "detect.binary is required"),
        ({"safety": "yolo"}, "safety"),
        (
            {"options": [{"id": "fast", "flag": "-f", "type": "choice"}]},
            "a choice needs choices",
        ),
        (
            {"options": [{"id": "fast", "flag": "-f", "when": {"moon": ["full"]}}]},
            "unknown when key",
        ),
    ],
)
def test_manifest_validation_errors(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        manifest_to_spec(_minimal(**change))


def test_choice_values_are_text() -> None:
    whatweb = get_tool("whatweb")
    aggression = whatweb.option("aggression")
    assert aggression.choices == ["1", "3", "4"] and aggression.default == "3"


def test_user_manifests_add_override_and_report_errors(tmp_path: Path) -> None:
    user_dir = Path(os.environ["XDG_CONFIG_HOME"]) / "cyberdeck" / "plugins" / "tools"
    user_dir.mkdir(parents=True)
    (user_dir / "demo.yaml").write_text(yaml.safe_dump(_minimal()), encoding="utf-8")
    custom = yaml.safe_load(
        (builtin_tools_dir() / "web" / "nikto.yaml").read_text(encoding="utf-8")
    )
    custom["description"] = "my nikto"
    (user_dir / "nikto.yaml").write_text(yaml.safe_dump(custom), encoding="utf-8")
    (user_dir / "broken.yaml").write_text("id: [", encoding="utf-8")
    reserved = _minimal(id="nmap-allports")
    (user_dir / "reserved.yaml").write_text(yaml.safe_dump(reserved), encoding="utf-8")

    reg = registry(reload=True)
    assert "demo" in reg.tools
    assert reg.tools["nikto"].description == "my nikto" and reg.overridden == ["nikto"]
    assert reg.tools["nmap-allports"].source is None  # built-in kept
    bad = {p.name for p, _ in reg.errors}
    assert bad == {"broken.yaml", "reserved.yaml"}


# --- detection, help, wordlists, hosts ------------------------------------------------------


def _fake_binary(directory: Path, name: str, output: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(f"#!/bin/sh\necho '{output}'\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.mark.skipif(os.name != "posix", reason="shell-script fake binary")
def test_detect_version_cache_and_help(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bindir = tmp_path / "bin"
    _fake_binary(bindir, "whatweb", "WhatWeb version 9.9.9 ( https://example )")
    monkeypatch.setenv("PATH", str(bindir))
    tool = get_tool("whatweb")
    status = detect(tool)
    assert status.installed and status.version == "9.9.9"

    _fake_binary(bindir, "whatweb", "WhatWeb version 1.0.0")
    os.utime(bindir / "whatweb", (1, 1))  # mtime change invalidates the cache entry
    assert detect(tool).version == "1.0.0"
    help_text = tool_help(tool)
    assert help_text and "WhatWeb version" in help_text
    assert (Path(os.environ["XDG_CACHE_HOME"]) / "cyberdeck" / "help" / "whatweb.txt").is_file()

    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    missing = detect_all([get_tool("ffuf-vhost")])["ffuf-vhost"]
    assert not missing.installed and missing.install_hint == "sudo apt install ffuf"


def test_tool_env_drops_virtualenv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    venv_bin = str(Path(sys.prefix) / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([venv_bin, "/usr/bin"]))
    monkeypatch.setenv("VIRTUAL_ENV", sys.prefix)
    env = runner_mod.tool_env()
    if sys.prefix != sys.base_prefix:
        assert venv_bin not in env["PATH"].split(os.pathsep) and "VIRTUAL_ENV" not in env
    assert "/usr/bin" in env["PATH"]


def test_wordlists_resolve_and_override(tmp_path: Path) -> None:
    mine = tmp_path / "mine.txt"
    mine.write_text("admin\n", encoding="utf-8")
    resolved = wordlists.resolve("dirs_small", {"dirs_small": str(mine)})
    assert resolved and resolved.exists and resolved.overridden and resolved.path == mine
    assert wordlists.resolve("unknown-list") is None
    ctx = wordlists.context({"custom": str(mine)})
    assert ctx["wordlists.custom"] == str(mine) and "wordlists.vhosts" in ctx


def test_parse_hosts() -> None:
    names = parse_hosts("127.0.0.1 localhost\n10.129.1.1 box.htb dev.box.htb # cyberdeck:box\n")
    assert names["dev.box.htb"] == ["10.129.1.1"] and "localhost" in names


# --- parsers on real-shaped fixtures --------------------------------------------------------


def _ctx(tmp_path: Path, fixture: str, tool: str = "t", **values: Any) -> ParseContext:  # helper
    return ParseContext(
        tool_id=tool,
        job_id=7,
        target_ip=IP,
        workspace=tmp_path,
        stdout=tmp_path / "missing.out",
        stderr=tmp_path / "missing.err",
        outputs=[TOOL_FIXTURES / fixture],
        values=values,
        ctx={"target.ip": IP},
        config=get_tool(tool).parser_config if tool != "t" else {},
    )


def _of(findings: list[Finding], kind: FindingType) -> list[Finding]:
    return [f for f in findings if f.type is kind]


def test_whatweb_parser(tmp_path: Path) -> None:
    found = run_parser("whatweb_json", _ctx(tmp_path, "whatweb.json"))
    software = {
        f.as_(Software).name: f.as_(Software).version for f in _of(found, FindingType.SOFTWARE)
    }
    assert software == {"JQuery": "3.6.0", "nginx": "1.18.0", "PHP": "8.1.2", "WordPress": "6.4.2"}
    (url,) = [f.as_(Url) for f in _of(found, FindingType.URL)]
    assert url.status == 200 and url.title == "Lantern - Home"
    assert all(f.sources == ["job:7:t"] for f in found)

    redirect = run_parser("whatweb_json", _ctx(tmp_path, "whatweb-redirect.json"))
    (host,) = [f.as_(Hostname) for f in _of(redirect, FindingType.HOSTNAME)]
    assert host.fqdn == "lantern.htb" and host.ip == IP and host.origins == ["whatweb:redirect"]
    (url,) = [f.as_(Url) for f in _of(redirect, FindingType.URL)]
    assert url.redirect == "http://lantern.htb/" and url.status == 302


def test_whatweb_parser_survives_truncated_output(tmp_path: Path) -> None:
    text = (TOOL_FIXTURES / "whatweb.json").read_text(encoding="utf-8").rstrip().rstrip("]")
    partial = tmp_path / "partial.json"
    partial.write_text(text, encoding="utf-8")
    ctx = _ctx(tmp_path, "whatweb.json")
    ctx = ParseContext(**{**ctx.__dict__, "outputs": [partial]})
    assert _of(run_parser("whatweb_json", ctx), FindingType.SOFTWARE)


@pytest.mark.parametrize(
    ("parser_name", "fixture"),
    [
        ("feroxbuster_json", "feroxbuster.json"),
        ("gobuster_dir", "gobuster.txt"),
        ("dirsearch_json", "dirsearch.json"),
    ],
)
def test_dir_bruteforce_parsers(tmp_path: Path, parser_name: str, fixture: str) -> None:
    found = run_parser(parser_name, _ctx(tmp_path, fixture, url="http://lantern.htb/"))
    urls = {f.as_(Url).url: f.as_(Url) for f in _of(found, FindingType.URL)}
    assert (
        "http://lantern.htb/backup.zip" in urls
        and urls["http://lantern.htb/backup.zip"].status == 200
    )
    assert urls["http://lantern.htb/admin"].redirect == "http://lantern.htb/admin/"
    assert urls["http://lantern.htb/robots.txt"].length == 36
    hosts = {f.as_(Hostname).fqdn for f in _of(found, FindingType.HOSTNAME)}
    assert hosts == {"lantern.htb"}


def test_ffuf_dir_parser(tmp_path: Path) -> None:
    found = run_parser(
        "ffuf_dir", _ctx(tmp_path, "ffuf-dir.json", tool="ffuf-dir", url=f"http://{IP}/")
    )
    urls = {f.as_(Url).url: f.as_(Url) for f in _of(found, FindingType.URL)}
    assert urls[f"http://{IP}/backup.zip"].status == 200
    assert urls[f"http://{IP}/admin"].redirect == "http://lantern.htb/admin/"
    assert [f.as_(Hostname).fqdn for f in _of(found, FindingType.HOSTNAME)] == ["lantern.htb"]


def test_ffuf_vhost_parser(tmp_path: Path) -> None:
    found = run_parser(
        "ffuf_vhost", _ctx(tmp_path, "ffuf-vhost.json", url=f"http://{IP}/", domain="lantern.htb")
    )
    (host,) = [f.as_(Hostname) for f in _of(found, FindingType.HOSTNAME)]
    assert host.fqdn == "dev.lantern.htb" and host.ip == IP
    (url,) = [f.as_(Url) for f in _of(found, FindingType.URL)]
    assert url.url == "http://dev.lantern.htb/" and url.status == 200
    on_port = run_parser(
        "ffuf_vhost",
        _ctx(tmp_path, "ffuf-vhost.json", url=f"http://{IP}:8080/", domain="lantern.htb"),
    )
    assert [f.as_(Url).url for f in _of(on_port, FindingType.URL)] == [
        "http://dev.lantern.htb:8080/"
    ]


def test_nikto_lines_regex(tmp_path: Path) -> None:
    found = run_parser(
        "lines_regex", _ctx(tmp_path, "nikto.txt", tool="nikto", url=f"http://{IP}/")
    )
    software = {
        (f.as_(Software).name, f.as_(Software).version, f.as_(Software).where) for f in found
    }
    assert ("nginx", "1.18.0", f"http://{IP}/") in software and (
        "PHP",
        "8.1.2",
        f"http://{IP}/",
    ) in software
    assert all("outdated" in f.tags for f in found)


def test_lines_regex_vuln_and_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "out.txt"
    out.write_text(
        "+ GET /x: Apache is vulnerable to CVE-2021-41773 path traversal.\n", encoding="utf-8"
    )
    ctx = ParseContext(
        "nikto",
        1,
        IP,
        tmp_path,
        out,
        out,
        [],
        {"url": "http://x.htb/"},
        {},
        get_tool("nikto").parser_config,
    )
    (vuln,) = [f.as_(Vuln) for f in run_parser("lines_regex", ctx)]
    assert vuln.id == "CVE-2021-41773" and vuln.where == "http://x.htb/"

    lines = tmp_path / "lines.jsonl"
    lines.write_text('{"kind":"hit","u":"http://x.htb/a","code":200}\n{"kind":"stat"}\nnot json\n')
    cfg = {"type": "url", "fields": {"url": "u", "status": "code"}, "match": {"kind": "hit"}}
    ctx = ParseContext("t", 1, IP, tmp_path, lines, lines, [], {}, {}, cfg)
    (url,) = run_parser("jsonl", ctx)
    assert url.as_(Url).status == 200


def test_unknown_and_failing_parsers(tmp_path: Path) -> None:
    with pytest.raises(ParserError, match="no parser"):
        get_parser("nope")
    parsers_dir = Path(os.environ["XDG_CONFIG_HOME"]) / "cyberdeck" / "plugins" / "parsers"
    parsers_dir.mkdir(parents=True)
    (parsers_dir / "mine.py").write_text(
        "from cyberdeck.plugins.parsers import parser\n"
        "@parser('boom_test')\n"
        "def boom(ctx):\n    raise RuntimeError('kaput')\n",
        encoding="utf-8",
    )
    with pytest.raises(ParserError, match="kaput"):
        run_parser("boom_test", _ctx(tmp_path, "whatweb.json"))


# --- planning -------------------------------------------------------------------------------


def test_plan_web_tool_uses_ip_until_hosts_entry(
    lantern: Workspace, settings: Settings, tmp_path: Path
) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    settings = settings.model_copy(update={"hosts_file": hosts})
    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    assert plan.values["url"] == f"http://{IP}/"
    assert any("lantern.htb is not in" in w for w in plan.warnings)
    assert plan.argv()[-1] == f"http://{IP}/"
    assert plan.output_paths()[0].startswith("raw/whatweb-") and not plan.problems(False)

    hosts.write_text(f"{IP} lantern.htb\n", encoding="utf-8")
    plan = services.plan_tool(lantern, "whatweb", settings=settings)
    assert plan.values["url"] == "http://lantern.htb/"
    assert any("Other web services" in w for w in plan.warnings) is False


def test_plan_ffuf_vhost_and_when_options(lantern: Workspace, settings: Settings) -> None:
    plan = services.plan_tool(lantern, "ffuf-vhost", settings=settings)
    argv = plan.argv()
    assert argv[argv.index("-H") + 1] == "Host: FUZZ.lantern.htb"
    assert plan.values["url"] == f"http://{IP}/"
    assert plan.values["wordlist"] == str(wordlists.resolve("vhosts").path)  # type: ignore[union-attr]

    ferox = services.plan_tool(lantern, "feroxbuster", settings=settings)
    assert ferox.values["extensions"] is None and "-x" not in ferox.argv()  # no PHP seen yet
    with lantern.store() as store:
        store.upsert(Finding.of(Software(name="PHP", version="8.1.2"), source="test"))
    ferox = services.plan_tool(lantern, "feroxbuster", settings=settings)
    assert ferox.values["extensions"] == "php,txt"


def test_presets_expand_wordlists_and_missing_wordlist_is_a_problem(
    lantern: Workspace, settings: Settings, tmp_path: Path
) -> None:
    plan = services.plan_tool(lantern, "feroxbuster", preset="quick", settings=settings)
    assert plan.values["wordlist"] == str(wordlists.resolve("dirs_small").path)  # type: ignore[union-attr]
    plan.set_option("wordlist", str(tmp_path / "nope.txt"))
    assert any("wordlist not found" in p for p in plan.problems(False))
    plan.set_option("wordlist", "{wordlists.vhosts}")
    assert "{" not in plan.values["wordlist"]


def test_missing_input_is_a_problem(settings: Settings) -> None:
    ws = make_ws(settings, "empty", IP)
    plan = services.plan_tool(ws, "whatweb", settings=settings)
    assert any("No web service known" in w for w in plan.warnings)
    assert any("URL is needed" in p for p in plan.problems(False))
    plan.set_option("url", f"http://{IP}:8080/")
    assert not plan.problems(False)


def test_saved_defaults_skip_inputs(lantern: Workspace, settings: Settings) -> None:
    plan = services.plan_tool(lantern, "feroxbuster", settings=settings)
    plan.set_option("depth", "4")
    plan.set_option("url", "http://elsewhere.htb/")
    assert plan.changed_values() == {"depth": 4}


# --- groups, enable/disable -----------------------------------------------------------------


def _installed(monkeypatch: pytest.MonkeyPatch, *ids: str) -> None:
    def fake(tool: Any, **_: Any) -> ToolStatus:
        path = f"/usr/bin/{tool.binary}" if tool.id in ids else None
        return ToolStatus(tool.id, tool.binary, path, "1.0" if path else None, None)

    monkeypatch.setattr(services, "detect", fake)
    monkeypatch.setattr(
        services, "detect_all", lambda tools, refresh=False: {t.id: fake(t) for t in tools}
    )


def test_group_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(monkeypatch, "gobuster-dir", "dirsearch")
    assert services.resolve_tool("dir-bruteforce").id == "gobuster-dir"  # ferox missing
    services.prefer_tool("dirsearch")
    assert services.resolve_tool("dir-bruteforce").id == "dirsearch"
    services.set_tool_enabled("dirsearch", False)
    assert services.resolve_tool("dir-bruteforce").id == "gobuster-dir"
    assert load_user_config().disabled_tools == ["dirsearch"]
    services.set_tool_enabled("dirsearch", True)
    assert load_user_config().disabled_tools == []
    infos = {i.tool.id: i for i in services.tool_infos()}
    assert infos["dirsearch"].preferred and not infos["gobuster-dir"].preferred
    assert services.resolve_tool("whatweb").id == "whatweb"
    with pytest.raises(OptionError, match="unknown tool or group"):
        services.resolve_tool("nope")
    with pytest.raises(OptionError, match="not part of an alternatives group"):
        services.prefer_tool("nmap-udp")
    _installed(monkeypatch)
    with pytest.raises(OptionError, match="sudo apt install"):
        services.resolve_tool("vhost-fuzz")


# --- running, parsing, re-parsing ------------------------------------------------------------


@pytest.fixture
def fake_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        services,
        "RUNNER_LAUNCHER",
        lambda argv: [sys.executable, str(FAKE_TOOL), *argv[1:]],
    )


async def test_execute_parses_and_reparse_is_idempotent(
    lantern: Workspace, settings: Settings, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "feroxbuster.json"))
    plan = services.plan_tool(lantern, "feroxbuster", settings=settings)
    plan.set_option("url", "http://lantern.htb/")
    outcome = await services.execute_plan(lantern, settings, plan)
    assert outcome.result.ok and outcome.parse_report is not None
    created = outcome.parse_report.created
    assert len(_of(created, FindingType.URL)) == 7
    job = outcome.result.job
    assert job.meta["outputs"] == plan.output_paths() and job.meta["values"]["url"]
    assert all(f.sources == [f"job:{job.id}:feroxbuster"] for f in created)

    again = services.reparse_job(lantern, job.id)
    assert again.error is None and again.created == [] and again.updated == []
    with pytest.raises(OptionError, match="no job"):
        services.reparse_job(lantern, 999)


async def test_failed_job_still_parsed_and_parse_errors_noted(
    lantern: Workspace, settings: Settings, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "nikto.txt"))
    monkeypatch.setenv("FAKE_TOOL_EXIT", "1")
    plan = services.plan_tool(lantern, "nikto", settings=settings)
    outcome = await services.execute_plan(lantern, settings, plan)
    assert not outcome.result.ok
    # PHP/8.1.2 is named twice (header and 'outdated' line): one software finding
    assert outcome.parse_report and len(outcome.parse_report.created) == 1

    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "gobuster.txt"))
    monkeypatch.setattr(
        "cyberdeck.core.services.run_parser",
        lambda name, ctx: (_ for _ in ()).throw(ParserError("bad output")),
    )
    plan = services.plan_tool(lantern, "gobuster-dir", settings=settings)
    outcome = await services.execute_plan(lantern, settings, plan)
    assert any("parsing failed: bad output" in n for n in outcome.notes)


async def test_reparse_nmap_job(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import shutil

    fixtures = tmp_path / "fx"
    fixtures.mkdir()
    shutil.copy(FIXTURES / "lantern" / "lantern.xml", fixtures / "services.xml")
    monkeypatch.setenv("FAKE_NMAP_FIXTURES", str(fixtures))
    fake_nmap = Path(__file__).parent / "fake_nmap.py"
    monkeypatch.setattr(
        services, "RUNNER_LAUNCHER", lambda argv: [sys.executable, str(fake_nmap), *argv[1:]]
    )
    ws = make_ws(settings, "lantern", IP)
    plan = services.plan_tool(ws, "nmap-services", overrides={"ports": "22,80"}, settings=settings)
    outcome = await services.execute_plan(ws, settings, plan)
    report = services.reparse_job(ws, outcome.result.job.id)
    assert report.error is None and report.created == []


# --- CLI ------------------------------------------------------------------------------------

cli_runner = CliRunner()


def test_cli_tools_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "console", Console(width=200))
    _installed(monkeypatch, "feroxbuster", "whatweb")
    result = cli_runner.invoke(cli.app, ["tools"])
    assert result.exit_code == 0, result.output
    assert "feroxbuster *" in result.output and "sudo apt install gobuster" in result.output
    result = cli_runner.invoke(cli.app, ["tools", "prefer", "gobuster-dir"])
    assert result.exit_code == 0 and load_user_config().group_prefs == {
        "dir-bruteforce": "gobuster-dir"
    }
    result = cli_runner.invoke(cli.app, ["tools", "disable", "nikto"])
    assert result.exit_code == 0 and "nikto" in load_user_config().disabled_tools
    result = cli_runner.invoke(cli.app, ["tools", "prefer", "nope"])
    assert result.exit_code == 1
    result = cli_runner.invoke(cli.app, ["tools", "wordlists"])
    assert result.exit_code == 0 and "dirs_medium" in result.output
    result = cli_runner.invoke(cli.app, ["run", "list"])
    assert result.exit_code == 0 and "dir-bruteforce" in result.output


def test_cli_run_manifest_tool(
    lantern: Workspace, fake_tool: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "console", Console(width=200))
    monkeypatch.setattr(cli, "have_binary", lambda name: True)
    monkeypatch.setattr(services, "vpn_check", lambda s, ip: _vpn_up(ip))
    _installed(monkeypatch, "whatweb", "feroxbuster")
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "whatweb-redirect.json"))
    result = cli_runner.invoke(cli.app, ["run", "web-fingerprint", "-t", str(lantern.path), "-y"])
    assert result.exit_code == 0, result.output
    assert "$ whatweb" in result.output and "new findings" in result.output
    result = cli_runner.invoke(cli.app, ["reparse", "1", "-t", str(lantern.path)])
    assert result.exit_code == 0 and "0 new findings" in result.output


def _vpn_up(ip: str) -> Any:
    from cyberdeck.util.vpn import Tunnel, VpnStatus

    return VpnStatus(ip, True, [Tunnel("tun0", "10.10.14.7")], route_dev="tun0")


def test_user_config_roundtrip_new_fields() -> None:
    cfg = load_user_config()
    cfg.wordlists["dirs_small"] = "/tmp/x.txt"  # noqa: S108
    save_user_config(cfg)
    assert load_user_config().wordlists == {"dirs_small": "/tmp/x.txt"}  # noqa: S108


def test_runplan_full_context_skips_empty_inputs() -> None:
    tool = manifest_to_spec(_minimal())
    plan = RunPlan(tool, {"url": None, "fast": True}, {"target.ip": IP})
    assert "url" not in plan.full_context()
    with pytest.raises(OptionError, match="is needed"):
        plan.argv()


def test_plan_warns_when_ports_closed_or_tool_missing(settings: Settings) -> None:
    """rpcclient on a box without SMB only times out: say so before it runs."""
    from cyberdeck.core.models import Finding, Service

    ws = make_ws(settings, "kiosk", "10.10.11.9")
    with ws.store() as store:
        store.upsert(Finding.of(Service(port=135, name="msrpc"), source="test"))
    plan = services.plan_tool(ws, "rpcclient-enum")
    assert any("445, 139" in w and "time out" in w for w in plan.warnings)
    assert not any("time out" in w for w in services.plan_tool(ws, "impacket-rpcdump").warnings)
    tool = registry().tools["rpcclient-enum"]
    missing = tool.model_copy(update={"binary": "no-such-binary-xyz", "detect": None})
    from cyberdeck.core.facts import BoxFacts
    from cyberdeck.core.services import _readiness_warnings

    warned = _readiness_warnings(missing, BoxFacts([], [], [], []))
    assert warned == ["no-such-binary-xyz is not installed: sudo apt install no-such-binary-xyz"]


PAGE_DUMP = """HTTP/1.1 302 Found\r
Location: /login\r
Server: Microsoft-HTTPAPI/2.0\r
\r
HTTP/1.1 200 OK\r
Content-Type: text/html; charset=utf-8\r
X-Powered-By: Express\r
\r
<!DOCTYPE html><html><head><title>Acme DeviceHub - Login</title></head><body>
<!-- TODO remove test account before release -->
<div class="sub">DeviceHub firmware v2.4.1</div>
<form method="POST" action="/login"><input type="password" name="password"
 placeholder="Device password"></form>
<button onclick="scan()">Scan</button>
<div title="The default password is the serial number on the box.">Forgot your password?</div>
<script>function scan(){fetch('/login/badge',{method:'POST'}).then(r=>r.json())}
fetch('/api/status').then(r=>r.json())</script></body></html>
"""


def test_html_inspect_reads_product_hints_and_endpoints(tmp_path: Path) -> None:
    from cyberdeck.plugins.parsers import ParseContext, load_all, run_parser

    load_all()
    page = tmp_path / "page.txt"
    page.write_text(PAGE_DUMP, encoding="utf-8")
    ctx = ParseContext(
        tool_id="page-inspect",
        job_id=1,
        target_ip=IP,
        workspace=tmp_path,
        stdout=tmp_path / "missing.out",
        stderr=tmp_path / "missing.err",
        outputs=[page],
        values={"url": "http://box.htb:8443/"},
    )
    found = run_parser("html_inspect", ctx)
    by_type: dict[str, list[dict[str, Any]]] = {}
    for f in found:
        by_type.setdefault(f.type.value, []).append({**f.data, "tags": f.tags})
    urls: dict[str, dict[str, Any]] = {}
    for u in by_type["url"]:  # the page and its form are both /login: merge like the store
        merged = urls.setdefault(u["url"], {"tags": []})
        merged.update({k: v for k, v in u.items() if v and k != "tags"})
        merged["tags"] += u["tags"]
    # redirect followed: the page is /login, with its title
    assert urls["http://box.htb:8443/login"]["title"] == "Acme DeviceHub - Login"
    # endpoints from the form and from JavaScript, with their methods
    assert {"js", "post"} <= set(urls["http://box.htb:8443/login/badge"]["tags"])
    assert "get" in urls["http://box.htb:8443/api/status"]["tags"]
    assert "post" in urls["http://box.htb:8443/login"]["tags"]
    software = {(s["name"], s.get("version")) for s in by_type["software"]}
    assert ("Acme DeviceHub", "2.4.1") in software and ("Express", None) in software
    hints = [n["text"] for n in by_type["note"]]
    assert any("serial number" in h for h in hints)
    assert any("TODO remove test account" in h for h in hints)
    assert not any(h == "Device password" for h in hints)  # a placeholder is not a hint


async def test_plan_rerun_restores_values_and_edits(
    lantern: Workspace, settings: Settings, fake_tool: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TOOL_FIXTURE", str(TOOL_FIXTURES / "feroxbuster.json"))
    plan = services.plan_tool(lantern, "feroxbuster", settings=settings)
    plan.set_option("url", "http://lantern.htb/")
    plan.set_option("depth", "4")
    plan.set_extra("--rate-limit 20")
    first = (await services.execute_plan(lantern, settings, plan)).result.job
    again = services.plan_rerun(lantern, first.id, settings)
    assert again.raw_argv is None  # rebuilt from options: still editable field by field
    assert again.values["url"] == "http://lantern.htb/" and again.values["depth"] == 4
    assert again.extra == ["--rate-limit", "20"]
    old_out, new_out = first.meta["ctx"]["out"], again.ctx["out"]
    argv = again.argv()
    assert argv == [a.replace(old_out, new_out) for a in first.argv]

    # a hand-edited command comes back as the edited command, with a fresh output folder
    plan.set_raw(plan.command_line() + " --silent")
    edited = (await services.execute_plan(lantern, settings, plan)).result.job
    again = services.plan_rerun(lantern, edited.id, settings)
    assert again.raw_argv is not None and again.raw_argv[-1] == "--silent"
    old_out, new_out = edited.meta["ctx"]["out"], again.ctx["out"]
    assert again.raw_argv == [a.replace(old_out, new_out) for a in edited.argv]
    with pytest.raises(OptionError, match="no job"):
        services.plan_rerun(lantern, 999, settings)
