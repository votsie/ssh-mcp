import os
from pathlib import Path

import pytest

from conftest import TRICKY_PASSWORDS
from ssh_mcp import store
from ssh_mcp.store import ServerProfile, StoreError


def _profile(name: str = "nl9", **kw) -> ServerProfile:
    base = dict(name=name, host="192.0.2.9", user="root", password="s3cr3t-pass")
    base.update(kw)
    return ServerProfile(**base)


@pytest.mark.parametrize("password", TRICKY_PASSWORDS)
def test_password_survives_round_trip(store_path: Path, password: str) -> None:
    store.save(_profile(password=password), path=store_path)
    assert store.load(store_path)["nl9"].password == password


def test_all_fields_round_trip(store_path: Path) -> None:
    original = _profile(
        label="NL9 - BGD",
        domain="nl9.example.com",
        port=2222,
        user="admin",
        key_file="/home/user/.ssh/id_ed25519",
        passphrase="phrase with spaces",
        auth="key",
        tags=["owner:bgd", "imported"],
    )
    store.save(original, path=store_path)
    loaded = store.load(store_path)["nl9"]
    for field in ("host", "user", "port", "password", "key_file",
                  "passphrase", "auth", "label", "domain", "tags"):
        assert getattr(loaded, field) == getattr(original, field), field
    assert loaded.added, "штамп added должен проставляться автоматически"


def test_file_is_owner_only(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    mode = os.stat(store_path).st_mode & 0o777
    if os.name == "nt":
        # На NTFS POSIX-биты не показательны; проверяем, что icacls снял
        # наследование и оставил единственную явную ACE.
        import subprocess

        out = subprocess.run(
            ["icacls", str(store_path)], capture_output=True, text=True
        ).stdout
        assert os.environ["USERNAME"] in out
        assert "BUILTIN" not in out and "NT AUTHORITY" not in out, out
    else:
        assert mode == 0o600, oct(mode)


def test_temp_file_is_cleaned_up(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    assert not store_path.with_suffix(store_path.suffix + ".tmp").exists()


def test_backup_is_kept(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    store.save(_profile(host="192.0.2.10"), path=store_path, overwrite=True)
    assert store_path.with_suffix(store_path.suffix + ".bak").exists()


def test_refuses_to_clobber_a_different_host(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    with pytest.raises(StoreError, match="overwrite"):
        store.save(_profile(host="192.0.2.99"), path=store_path)


def test_overwrite_replaces(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    store.save(_profile(host="192.0.2.99"), path=store_path, overwrite=True)
    assert store.load(store_path)["nl9"].host == "192.0.2.99"


def test_same_host_twice_is_idempotent(store_path: Path) -> None:
    """Повторное сохранение того же адреса не должно требовать overwrite."""
    store.save(_profile(), path=store_path)
    store.save(_profile(label="переименовали"), path=store_path)
    assert store.load(store_path)["nl9"].label == "переименовали"


@pytest.mark.parametrize("bad", ["", "  ", "-leading", "имя", "a" * 33, "up/slash"])
def test_bad_names_rejected(store_path: Path, bad: str) -> None:
    with pytest.raises(StoreError):
        store.save(_profile(name=bad), path=store_path)


def test_hyphen_in_name_round_trips(store_path: Path) -> None:
    """Слаг NL_9 не должен «съесть» дефис из настоящего имени."""
    store.save(_profile(name="nl-9"), path=store_path)
    assert "nl-9" in store.load(store_path)


def test_delete(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    assert store.delete("nl9", store_path) is True
    assert store.load(store_path) == {}
    assert store.delete("nl9", store_path) is False


def test_foreign_keys_are_preserved(store_path: Path) -> None:
    store_path.write_text("MY_OWN_SETTING='keep me'\n", encoding="utf-8")
    store.save(_profile(), path=store_path)
    text = store_path.read_text(encoding="utf-8")
    assert "MY_OWN_SETTING='keep me'" in text


def test_hand_edited_bare_value_is_read(store_path: Path) -> None:
    """Конфиг правится блокнотом — значение без кавычек обязано читаться."""
    store_path.write_text(
        "SSHM_HAND_NAME=hand\nSSHM_HAND_HOST=192.0.2.41\n"
        "SSHM_HAND_USER=root\nSSHM_HAND_PASSWORD=aXc#,,Q_31ZmT9\n",
        encoding="utf-8",
    )
    loaded = store.load(store_path)["hand"]
    assert loaded.host == "192.0.2.41"
    assert loaded.password == "aXc#,,Q_31ZmT9"


def test_validate_flags_duplicates_and_bad_port(store_path: Path) -> None:
    profiles = {
        "a": ServerProfile(name="a", host="192.0.2.51"),
        "b": ServerProfile(name="b", host="192.0.2.51"),
        "c": ServerProfile(name="c", host="192.0.2.52", port=70000),
        "d": ServerProfile(name="d", host="192.0.2.53", jump="nowhere"),
    }
    problems = " | ".join(store.validate(profiles))
    assert "тот же адрес" in problems
    assert "вне диапазона" in problems
    assert "jump-хост" in problems


def test_touch_last_ok(store_path: Path) -> None:
    store.save(_profile(), path=store_path)
    store.touch_last_ok("nl9", store_path)
    assert store.load(store_path)["nl9"].last_ok
    store.touch_last_ok("does-not-exist", store_path)  # не должно падать


def test_profile_public_hides_secrets(store_path: Path) -> None:
    public = _profile(passphrase="phrase").public()
    assert "password" not in public and "passphrase" not in public
    assert public["has_password"] is True


def test_key_file_and_last_ok_do_not_spawn_phantom_servers(store_path: Path) -> None:
    """
    Регрессия: жадный разбор ключей растаскивал SSHM_NL1_KEY_FILE на слаг
    NL1_KEY и поле FILE, создавая профили из воздуха.
    """
    store.save(
        _profile(name="nl1", key_file="C:/keys/id", passphrase="phrase"),
        path=store_path,
    )
    store.touch_last_ok("nl1", store_path)
    loaded = store.load(store_path)
    assert sorted(loaded) == ["nl1"], f"лишние профили: {sorted(loaded)}"
    assert loaded["nl1"].key_file == "C:/keys/id"
    assert loaded["nl1"].last_ok


def test_underscored_name_round_trips(store_path: Path) -> None:
    store.save(_profile(name="ru_1"), path=store_path)
    assert sorted(store.load(store_path)) == ["ru_1"]
