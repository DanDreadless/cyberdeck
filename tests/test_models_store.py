from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from cyberdeck.core.models import (
    Credential,
    Finding,
    FindingType,
    Hostname,
    Service,
    merge_data,
    normalise_fqdn,
)
from cyberdeck.store.db import MIGRATIONS, Store


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Box.HTB.", "box.htb"),
        ("dc01.corp.htb", "dc01.corp.htb"),
        ("localhost", None),
        ("10.129.1.2", None),
        ("bad_-.htb", None),
        ("2.1.129.10.in-addr.arpa", None),
        ("", None),
    ],
)
def test_normalise_fqdn(raw: str, expected: str | None) -> None:
    assert normalise_fqdn(raw) == expected


def test_hostname_rejects_junk() -> None:
    with pytest.raises(ValidationError):
        Hostname(fqdn="not a host")


def test_service_url_and_banner() -> None:
    web = Service(port=443, name="http", tunnel="ssl", product="nginx", version="1.24.0")
    assert web.url("box.htb") == "https://box.htb/"
    assert Service(port=8080, name="http-proxy").url("box.htb") == "http://box.htb:8080/"
    assert Service(port=22, name="ssh").url("box.htb") is None
    assert web.banner == "nginx 1.24.0"


def test_credential_key_hides_secret() -> None:
    cred = Credential(user="admin", secret="Password123!")
    assert "Password123" not in cred.natural_key()


def test_merge_rules() -> None:
    merged, conflicts = merge_data(
        {"name": "http", "product": None, "cpe": ["a"], "scripts": {"x": "1"}},
        {"name": "http", "product": "nginx", "cpe": ["a", "b"], "scripts": {"y": "2"}},
        old_confidence=0.3,
        new_confidence=1.0,
    )
    assert merged == {
        "name": "http",
        "product": "nginx",
        "cpe": ["a", "b"],
        "scripts": {"x": "1", "y": "2"},
    }
    assert conflicts == []

    merged, conflicts = merge_data(
        {"version": "1.0"}, {"version": "2.0"}, old_confidence=0.9, new_confidence=0.5
    )
    assert merged == {"version": "1.0"} and conflicts == ["version"]


def test_store_upsert_and_history(tmp_path: Path) -> None:
    with Store(tmp_path / "t.db") as store:
        assert store.schema_version == len(MIGRATIONS)
        low = Finding.of(Service(port=80, name="http"), source="scan1", confidence=0.3)
        first = store.upsert(low)
        assert first.created and first.finding.id is not None

        assert not store.upsert(low).data_changed  # identical re-insert is a no-op

        high = Finding.of(
            Service(port=80, name="http", product="nginx", version="1.18.0"),
            source="scan2",
            confidence=1.0,
        )
        second = store.upsert(high)
        assert not second.created and second.data_changed
        assert second.finding.confidence == 1.0
        assert second.finding.sources == ["scan1", "scan2"]

        conflicting = Finding.of(
            Service(port=80, name="http", version="9.9"), source="scan3", confidence=0.2
        )
        third = store.upsert(conflicting)
        assert third.conflicts == ("version",)
        svc = store.get(FindingType.SERVICE, "tcp/80")
        assert svc is not None and svc.as_(Service).version == "1.18.0"  # higher confidence kept
        assert len(store.history(svc.id or 0)) == 1  # only the real data change is recorded
        assert store.counts() == {FindingType.SERVICE: 1}

    with Store(tmp_path / "t.db") as reopened:  # migrations are idempotent
        assert len(reopened.findings()) == 1


def test_store_imports(tmp_path: Path) -> None:
    with Store(tmp_path / "t.db") as store:
        assert not store.has_import("abc")
        store.record_import(tmp_path / "a.xml", "abc", "xml")
        store.record_import(tmp_path / "a.xml", "abc", "xml")
        assert store.has_import("abc")


def test_finding_as_wrong_type() -> None:
    f = Finding.of(Service(port=1), source="x")
    with pytest.raises(TypeError):
        f.as_(Hostname)


def test_store_delete_and_replace(tmp_path: Path) -> None:
    from cyberdeck.core.models import Credential, Finding, FindingType
    from cyberdeck.store.db import Store

    with Store(tmp_path / "t.db") as store:
        a = store.upsert(Finding.of(Credential(user="bob", secret="pw1"), source="job:1:x")).finding
        b = store.upsert(Finding.of(Credential(user="amy", secret="pw2"), source="user")).finding
        fixed = Finding.of(Credential(user="bob", secret="pw1!"), source="user")
        stored = store.replace(FindingType.CREDENTIAL, a.key, fixed)
        assert stored.id == a.id and stored.data["secret"] == "pw1!"
        assert stored.sources == ["job:1:x", "user"]
        assert store.get(FindingType.CREDENTIAL, a.key) is None  # the key followed the data
        assert [h["old"]["secret"] for h in store.history(a.id or 0)] == ["pw1"]
        clash = Finding.of(Credential(user="amy", secret="pw2"), source="user")
        with pytest.raises(ValueError, match="already exists"):
            store.replace(FindingType.CREDENTIAL, stored.key, clash)
        assert store.delete(FindingType.CREDENTIAL, b.key) is not None
        assert store.delete(FindingType.CREDENTIAL, b.key) is None
        assert [f.data["user"] for f in store.findings(FindingType.CREDENTIAL)] == ["bob"]
        assert store.history(b.id or 0) == []
