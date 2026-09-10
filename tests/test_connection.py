import time

import paramiko
import pytest

from sshd import PASSWORD, USER, LoopbackSSHServer
from ssh_mcp import connection, hostkeys
from ssh_mcp.connection import AuthError, Connection, RemoteError
from ssh_mcp.store import ServerProfile


def _profile(sshd: LoopbackSSHServer, **kw) -> ServerProfile:
    base = dict(
        name="loop", host="127.0.0.1", port=sshd.port,
        user=USER, password=PASSWORD, auth="password",
    )
    base.update(kw)
    return ServerProfile(**base)


# ---------------------------------------------------------------- коннект


def test_password_auth_and_tofu_pin(sshd, tmp_path):
    profile = _profile(sshd)
    client, report = connection.connect(profile)
    try:
        assert report["auth_method"] == "password"
        assert report["action"] == "pinned-tofu"
        assert report["fingerprint"].startswith("SHA256:")
        assert (tmp_path / "known_hosts").exists()
    finally:
        client.close()


def test_second_connect_sees_known_host(sshd, tmp_path):
    profile = _profile(sshd)
    connection.connect(profile)[0].close()
    client, report = connection.connect(profile)
    try:
        assert report["action"] == "known", "ключ уже закреплён — повторного TOFU быть не должно"
    finally:
        client.close()


def test_changed_host_key_is_rejected(sshd, tmp_path):
    """После закрепления подмена ключа обязана прерывать подключение."""
    profile = _profile(sshd)
    connection.connect(profile)[0].close()

    sshd.host_key = paramiko.RSAKey.generate(2048)
    with pytest.raises(paramiko.BadHostKeyException):
        connection.connect(profile)


def test_wrong_password_raises_auth_error(sshd):
    with pytest.raises(AuthError, match="аутентификация не удалась"):
        connection.connect(_profile(sshd, password="nope"))


def test_auth_ladder_falls_back_to_password(sshd, tmp_path):
    """auth=auto с несуществующим ключом обязан дойти до пароля, а не упасть."""
    profile = _profile(sshd, auth="auto", key_file=str(tmp_path / "absent"))
    client, report = connection.connect(profile)
    try:
        assert report["auth_method"] == "password"
    finally:
        client.close()


def test_key_auth(sshd, tmp_path):
    key = paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate") \
        else paramiko.RSAKey.generate(2048)
    key_path = tmp_path / "id_test"
    key.write_private_key_file(str(key_path))
    sshd.authorized_key = key

    client, report = connection.connect(
        _profile(sshd, auth="key", key_file=str(key_path), password="")
    )
    try:
        assert report["auth_method"] == "key"
    finally:
        client.close()


# ------------------------------------------------------------------- run()


def test_run_returns_stdout_and_rc(conn):
    result = conn.run("echo hello")
    assert result.rc == 0 and result.ok
    assert result.out == "hello"


def test_nonzero_rc_is_not_an_exception_by_default(conn):
    result = conn.run("exit 3")
    assert result.rc == 3 and not result.ok


def test_check_true_raises(conn):
    with pytest.raises(RemoteError) as excinfo:
        conn.run("exit 3", check=True)
    assert excinfo.value.rc == 3
    assert "[loop]" in str(excinfo.value)


def test_both_streams_are_drained(conn):
    """
    Регрессия на клин канала: при большом выводе одновременно в stdout и
    stderr чтение одного потока упирается в окно и виснет навсегда.
    """
    result = conn.run("bigout 3000", timeout=60)
    assert result.rc == 0
    assert result.stdout.count("stdout line") == 3000
    assert result.stderr.count("stderr line") == 3000
    assert "stdout line 2999" in result.stdout, "хвост вывода не должен обрезаться"


def test_absolute_deadline_fires(conn):
    """
    chan.settimeout() при опросе не срабатывает никогда — таймаут держится
    только на абсолютном дедлайне. Проверяем, что он реально наступает.
    """
    started = time.monotonic()
    with pytest.raises(RemoteError, match="превышен таймаут"):
        conn.run("sleep-forever", timeout=2)
    elapsed = time.monotonic() - started
    assert 1.5 < elapsed < 6, f"дедлайн отработал за {elapsed:.1f} с"


def test_max_output_truncates_without_hanging(conn):
    result = conn.run("bigout 2000", timeout=60, max_output=5000)
    assert result.truncated is True
    assert len(result.stdout) <= 5000
    assert result.rc == 0, "усечение не должно ломать чтение кода возврата"


def test_alive_and_close(conn):
    assert conn.alive() is True
    conn.close()
    assert conn.alive() is False


def test_run_on_dead_transport_errors(conn):
    conn.close()
    with pytest.raises(RemoteError, match="транспорт неактивен"):
        conn.run("echo hi")


def test_passphrase_protected_key_gives_a_readable_error(tmp_path):
    """
    Регрессия: paramiko 5 сообщает о ключе под парольной фразой обычным
    TypeError. Непойманным он всплывал наружу как невнятный сбой.
    """
    from ssh_mcp.connection import load_private_key

    key = paramiko.RSAKey.generate(2048)
    path = tmp_path / "locked"
    key.write_private_key_file(str(path), password="фраза")

    with pytest.raises(AuthError, match="парольной фразой"):
        load_private_key(path)

    unlocked = load_private_key(path, "фраза")
    assert unlocked.get_name() == "ssh-rsa"


def test_auth_ladder_survives_a_locked_key(sshd, tmp_path):
    """Ключ под фразой не должен мешать войти паролем."""
    key = paramiko.RSAKey.generate(2048)
    path = tmp_path / "locked"
    key.write_private_key_file(str(path), password="фраза")

    client, report = connection.connect(
        _profile(sshd, auth="auto", key_file=str(path))
    )
    try:
        assert report["auth_method"] == "password"
    finally:
        client.close()


def test_wrong_passphrase_is_reported_clearly(tmp_path):
    """Неверная фраза должна называться так, а не «ключ защищён фразой»."""
    from ssh_mcp.connection import load_private_key

    key = paramiko.RSAKey.generate(2048)
    path = tmp_path / "locked2"
    key.write_private_key_file(str(path), password="правильная")

    with pytest.raises(AuthError, match="неверная парольная фраза"):
        load_private_key(path, "неправильная")


def test_jump_host_routes_through_a_channel(sshd, tmp_path, monkeypatch):
    """
    Прыжковый хост: до цели идём каналом, открытым с промежуточного сервера.
    Оба конца здесь — один и тот же локальный sshd, но путь настоящий.
    """
    from ssh_mcp import registry, store as store_module

    path = tmp_path / "servers.env"
    monkeypatch.setattr(store_module, "SERVERS_ENV", path)

    base = dict(host="127.0.0.1", port=sshd.port, user=USER,
                password=PASSWORD, auth="password")
    store_module.save(ServerProfile(name="hop", **base), path=path)
    store_module.save(ServerProfile(name="target", jump="hop", **base), path=path)

    registry.shutdown()
    try:
        handle = registry.acquire("target")
        assert handle.connection.host_key.get("via") == "hop"
        assert handle.connection.run("echo через-прыжок").out == "через-прыжок"
        assert any(c["name"] == "hop" for c in registry.connections()), \
            "промежуточное соединение обязано остаться в реестре"
    finally:
        registry.shutdown()


def test_jump_loop_is_detected(sshd, tmp_path, monkeypatch):
    from ssh_mcp import registry, store as store_module
    from ssh_mcp.registry import UnknownServer

    path = tmp_path / "servers.env"
    monkeypatch.setattr(store_module, "SERVERS_ENV", path)
    base = dict(host="127.0.0.1", port=sshd.port, user=USER,
                password=PASSWORD, auth="password")
    store_module.save(ServerProfile(name="a", jump="b", **base), path=path)
    store_module.save(ServerProfile(name="b", jump="a", **base), path=path)

    registry.shutdown()
    try:
        with pytest.raises(UnknownServer, match="кольцо"):
            registry.acquire("a")
    finally:
        registry.shutdown()
