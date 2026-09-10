from pathlib import Path

import pytest

from conftest import LEGACY_FILE
from ssh_mcp import legacy_import, store

BLOCK = """\
RU1 - BGD
198.51.100.11
root
aXc#,,Q_31ZmT9
ru1.example.com

NL3 - AA
203.0.113.23
root
hJ39kLmNpQrS
nl3.example.com
"""


def test_parses_two_clean_blocks() -> None:
    result = legacy_import.parse(BLOCK)
    assert [p.name for p in result.profiles] == ["ru1", "nl3"]
    assert result.skipped == []
    ru1 = result.profiles[0]
    assert ru1.host == "198.51.100.11"
    assert ru1.user == "root"
    assert ru1.password == "aXc#,,Q_31ZmT9"
    assert ru1.domain == "ru1.example.com"
    assert ru1.label == "RU1 - BGD"
    assert ru1.tags == ["owner:bgd", "imported"]
    assert ru1.auth == "password"


def test_trailing_junk_does_not_shift_blocks() -> None:
    """
    Регрессия на реальную поломку: посторонняя строка в конце файла при
    наивной нарезке по пять сдвинула бы разбор и перепутала пароли.
    """
    result = legacy_import.parse(
        BLOCK + "\nQwErTy123-AsDfGh456- -- пароль от панелей\n"
    )
    assert [p.name for p in result.profiles] == ["ru1", "nl3"]
    assert result.profiles[1].password == "hJ39kLmNpQrS"
    assert len(result.skipped) == 1


def test_junk_between_blocks_resyncs() -> None:
    head, tail = BLOCK.split("\n\n")
    result = legacy_import.parse(head + "\n\nмусор посреди файла\n\n" + tail)
    assert [p.name for p in result.profiles] == ["ru1", "nl3"]
    assert result.skipped == ["мусор посреди файла"]


def test_incomplete_block_is_skipped_not_guessed() -> None:
    result = legacy_import.parse("XX - AA\n10.0.0.1\nroot\n")
    assert result.profiles == []
    assert len(result.skipped) == 3


def test_password_that_looks_like_a_domain() -> None:
    """Пароль не валидируется — иначе доменоподобный пароль сломал бы разбор."""
    result = legacy_import.parse(
        "AA - X\n10.0.0.1\nroot\nlooks.like.a.domain\nreal.example.com\n"
    )
    assert result.profiles[0].password == "looks.like.a.domain"
    assert result.profiles[0].domain == "real.example.com"


def test_save_skipped_writes_file(tmp_path: Path) -> None:
    result = legacy_import.parse(BLOCK + "\nхвост с доступами к панели\n")
    out = result.save_skipped(tmp_path / "notes.md")
    assert out is not None
    assert "хвост с доступами к панели" in out.read_text(encoding="utf-8")


def test_save_skipped_noop_when_clean(tmp_path: Path) -> None:
    assert legacy_import.parse(BLOCK).save_skipped(tmp_path / "notes.md") is None


@pytest.mark.skipif(not LEGACY_FILE.exists(), reason="задайте SSHM_TEST_LEGACY_FILE")
def test_real_fleet_file(tmp_path: Path) -> None:
    result = legacy_import.parse_file(LEGACY_FILE)
    assert len(result.profiles) >= 1
    assert all(p.host and p.user for p in result.profiles)
    assert all(p.password and p.domain for p in result.profiles)

    path = tmp_path / "servers.env"
    written = store.save_many(result.profiles, path=path)
    assert sorted(written) == sorted(p.name for p in result.profiles)
    loaded = store.load(path)
    for parsed in result.profiles:
        assert loaded[parsed.name].password == parsed.password
    assert store.validate(loaded) == []


@pytest.mark.skipif(not LEGACY_FILE.exists(), reason="задайте SSHM_TEST_LEGACY_FILE")
def test_import_is_idempotent(tmp_path: Path) -> None:
    result = legacy_import.parse_file(LEGACY_FILE)
    path = tmp_path / "servers.env"
    store.save_many(result.profiles, path=path)
    again = store.save_many(result.profiles, path=path)
    assert again == [], "повторный импорт не должен ничего перезаписывать"
