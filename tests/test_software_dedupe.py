"""Software is one finding per product + version, wherever it was seen."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from cyberdeck.core.models import Finding, FindingType, Software
from cyberdeck.store.db import SOFTWARE_BY_NAME_VERSION, Store


def _sw(store: Store) -> list[Finding]:
    return store.findings(FindingType.SOFTWARE)


def _add(store: Store, name: str, version: str | None, where: str | None, src: str = "t") -> bool:
    sw = Software(name=name, version=version, where=where)
    return store.upsert(Finding.of(sw, source=src)).created


def test_same_software_on_http_and_https_is_one_finding(tmp_path: Path) -> None:
    with Store(tmp_path / "t.db") as store:
        assert _add(store, "PHP", "8.1.2", "http://box.htb/", "job:1:whatweb")
        assert not _add(store, "PHP", "8.1.2", "https://box.htb/", "job:2:whatweb")
        assert not _add(store, "php", "8.1.2", "http://box.htb/", "job:3:nikto")  # seen again
        (php,) = _sw(store)
        assert php.data["where"] == "http://box.htb/"  # the first place stays
        assert php.data["seen_at"] == ["http://box.htb/", "https://box.htb/"]
        assert php.sources == ["job:1:whatweb", "job:2:whatweb", "job:3:nikto"]


def test_versions_stay_apart_and_no_version_joins_the_versioned_one(tmp_path: Path) -> None:
    with Store(tmp_path / "t.db") as store:
        assert _add(store, "Apache", None, "tcp/80")
        assert not _add(store, "Apache", "2.4.52", "tcp/443")  # fills in the version
        (apache,) = _sw(store)
        assert apache.key == "apache@2.4.52" and apache.data["version"] == "2.4.52"
        assert not _add(store, "Apache", None, "http://box.htb/")  # nothing new
        assert _add(store, "Apache", "2.4.41", "tcp/8080")  # a different version is new
        assert sorted(f.key for f in _sw(store)) == ["apache@2.4.41", "apache@2.4.52"]


def test_old_boxes_get_their_duplicates_merged(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    with Store(db):
        pass
    conn = sqlite3.connect(db)
    rows = [
        (
            "php@8.1.2@http://box.htb/",
            {"name": "PHP", "version": "8.1.2", "where": "http://box.htb/"},
            "a",
        ),
        (
            "php@8.1.2@https://box.htb/",
            {"name": "PHP", "version": "8.1.2", "where": "https://box.htb/"},
            "b",
        ),
        ("nginx@?@tcp/80", {"name": "nginx", "version": None, "where": "tcp/80"}, "c"),
        ("nginx@1.18.0@tcp/80", {"name": "nginx", "version": "1.18.0", "where": "tcp/80"}, "d"),
    ]
    for key, data, src in rows:
        conn.execute(
            "INSERT INTO findings (type, key, data, confidence, sources, tags, created_at, "
            "updated_at) VALUES ('software', ?, ?, 0.8, ?, '[]', '2026-11-01T00:00:00+00:00', "
            "'2026-11-01T00:00:00+00:00')",
            (key, json.dumps(data), json.dumps([src])),
        )
    conn.execute(f"PRAGMA user_version = {SOFTWARE_BY_NAME_VERSION - 1}")
    conn.commit()
    conn.close()

    with Store(db) as store:
        found = {f.key: f for f in _sw(store)}
        assert set(found) == {"php@8.1.2", "nginx@1.18.0"}
        php = found["php@8.1.2"]
        assert php.id == 1 and php.sources == ["a", "b"]
        assert php.data["seen_at"] == ["http://box.htb/", "https://box.htb/"]
        assert found["nginx@1.18.0"].sources == ["c", "d"]
