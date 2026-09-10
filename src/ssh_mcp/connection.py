"""
Одно SSH-соединение: аутентификация, выполнение команд, файлы.

Ядро — цикл чтения в :meth:`Connection.run`, перенесённый из предыдущего
проекта без изменений по существу. Его свойства менять нельзя, каждое куплено болью:

* оба потока (stdout и stderr) вычерпываются на каждом проходе — чтение только
  одного заклинивает окно канала при большом выводе;
* выход из цикла требует ``exit_status_ready()`` И пустых обоих буферов —
  проверка одного лишь кода возврата обрезает хвост вывода;
* пауза 50 мс только когда данных не было — иначе busy-wait жжёт ядро;
* дедлайн абсолютный, по ``time.monotonic()``. ``chan.settimeout()`` при опросе
  не срабатывает никогда: блокирующего чтения нет, поэтому таймаут не наступает.
  Без дедлайна команда, отрезавшая нам же сеть (правка фаервола), висела бы до
  TCP-таймаута ОС. Под MCP это заняло бы рабочий поток навсегда.
"""

from __future__ import annotations

import hashlib
import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from .config import CONNECT_TIMEOUT, DEFAULT_CMD_TIMEOUT, KEEPALIVE, POLL_INTERVAL, log
from .hostkeys import TofuPolicy, load_all
from .store import ServerProfile

_TMP_SUFFIX = ".tmp.ssh-mcp"


class RemoteError(RuntimeError):
    """Ненулевой код возврата или сбой на удалённой стороне."""

    def __init__(self, server: str, cmd: str, rc: int, stdout: str, stderr: str):
        self.server, self.cmd, self.rc = server, cmd, rc
        self.stdout, self.stderr = stdout, stderr
        super().__init__(
            f"[{server}] rc={rc}: {cmd}\n"
            f"--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        )


class AuthError(RuntimeError):
    """Не удалось аутентифицироваться ни одним доступным способом."""


@dataclass
class Result:
    rc: int
    stdout: str
    stderr: str
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def out(self) -> str:
        return self.stdout.strip()


# --------------------------------------------------------------------- ключи

_key_cache: dict[tuple[str, str], paramiko.PKey] = {}
_key_lock = threading.Lock()


def _means_locked(exc: Exception) -> bool:
    """Сообщение о ключе под фразой. Текст зависит от формата ключа."""
    message = str(exc).lower()
    return "password" in message and ("not given" in message or "not provided" in message)


def _means_bad_passphrase(exc: Exception) -> bool:
    message = str(exc).lower()
    return "password" in message or "decrypt" in message or "mac" in message


def load_private_key(path: Path, passphrase: str = "") -> paramiko.PKey:
    """
    Загрузить приватный ключ любого поддерживаемого типа.

    ``getpass`` здесь не вызывается ни при каких обстоятельствах: у MCP-сервера
    нет терминала, и запрос пароля заблокировал бы процесс навсегда. Ключ под
    парольной фразой берётся либо с фразой из хранилища, либо через ssh-agent.
    """
    key = str(path)
    cache_key = (key, passphrase)
    with _key_lock:
        cached = _key_cache.get(cache_key)
    if cached is not None:
        return cached

    # Именно байты: paramiko принимает парольную фразу только так и на обычной
    # строке падает с «password must be bytes».
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        pkey = paramiko.PKey.from_path(path, password)
    except paramiko.PasswordRequiredException:
        raise
    except TypeError as exc:
        # О ключе под парольной фразой paramiko 5 сообщает обычным TypeError,
        # а не PasswordRequiredException. Непойманным он всплывал наружу
        # невнятным сбоем, минуя и остальные способы входа. Формулировка
        # зависит от формата ключа, поэтому проверяем по смыслу, а не буквально.
        if _means_locked(exc):
            raise AuthError(
                f"ключ {path} защищён парольной фразой. Укажите её в профиле "
                f"(поле passphrase) либо разблокируйте ключ один раз командой "
                f"ssh-add {path}"
            ) from exc
        raise
    except ValueError as exc:
        if _means_bad_passphrase(exc):
            raise AuthError(f"неверная парольная фраза для ключа {path}") from exc
        raise AuthError(f"не удалось прочитать ключ {path}: {exc}") from exc
    except (paramiko.SSHException, OSError) as exc:
        # Старые сборки paramiko не знают from_path — пробуем типы вручную.
        last: Exception = exc
        pkey = None
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                pkey = cls.from_private_key_file(key, password=password)
                break
            except paramiko.PasswordRequiredException:
                raise
            except (paramiko.SSHException, OSError, ValueError, TypeError) as inner:
                last = inner
        if pkey is None:
            if _means_locked(last):
                raise AuthError(
                    f"ключ {path} защищён парольной фразой. Укажите её в профиле "
                    f"(поле passphrase) либо разблокируйте ключ один раз командой "
                    f"ssh-add {path}"
                ) from last
            raise AuthError(f"не удалось прочитать ключ {path}: {last}") from last

    with _key_lock:
        _key_cache[cache_key] = pkey
    return pkey


def agent_keys() -> list[paramiko.PKey]:
    try:
        return list(paramiko.Agent().get_keys())
    except Exception:  # агент может отсутствовать целиком
        return []


# ------------------------------------------------------------------- коннект


def _auth_attempts(profile: ServerProfile) -> list[str]:
    """Порядок попыток аутентификации по режиму профиля."""
    if profile.auth == "password":
        return ["password"]
    if profile.auth == "key":
        return ["key"]
    if profile.auth == "agent":
        return ["agent"]
    order = []
    if profile.key_file:
        order.append("key")
    if agent_keys():
        order.append("agent")
    if profile.password:
        order.append("password")
    return order or ["password"]


def connect(profile: ServerProfile,
            sock: paramiko.Channel | None = None) -> tuple[paramiko.SSHClient, dict]:
    """
    Установить соединение. Возвращает клиента и отчёт о ключе хоста.

    Способы перебираются по лесенке, а не все сразу: paramiko при
    ``allow_agent=True`` молча пробует агента раньше пароля, и тогда
    невозможно понять, чем именно вошли.

    ``sock`` — готовый канал до сервера, когда идём через прыжковый хост.
    Проверка ключа хоста при этом не ослабевает: paramiko сверяет его по
    ``hostname``, то есть по настоящему адресу сервера, а не по каналу.
    """
    policy = TofuPolicy(profile.port)
    client = paramiko.SSHClient()
    client.get_host_keys().update(load_all())
    client.set_missing_host_key_policy(policy)

    common = dict(
        hostname=profile.host,
        port=profile.port,
        username=profile.user,
        timeout=CONNECT_TIMEOUT,
        banner_timeout=CONNECT_TIMEOUT,
        auth_timeout=CONNECT_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    if sock is not None:
        common["sock"] = sock

    attempts = _auth_attempts(profile)
    failures: list[str] = []
    for method in attempts:
        try:
            if method == "key":
                if not profile.key_file:
                    failures.append("key: файл ключа не задан")
                    continue
                pkey = load_private_key(
                    Path(profile.key_file).expanduser(), profile.passphrase
                )
                client.connect(pkey=pkey, **common)
            elif method == "agent":
                client.connect(**{**common, "allow_agent": True})
            else:
                if not profile.password:
                    failures.append("password: пароль не задан")
                    continue
                client.connect(password=profile.password, **common)

            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(KEEPALIVE)
            log.info("подключён %s способом %s", profile.endpoint, method)
            report = policy.report()
            report["auth_method"] = method
            return client, report

        except paramiko.BadHostKeyException:
            client.close()
            raise
        except (paramiko.AuthenticationException, paramiko.PasswordRequiredException) as exc:
            failures.append(f"{method}: {exc.__class__.__name__}")
        except AuthError as exc:
            failures.append(f"{method}: {exc}")

    client.close()
    raise AuthError(
        f"{profile.endpoint}: аутентификация не удалась. Пробовали: "
        + "; ".join(failures or attempts)
    )


# --------------------------------------------------------------- соединение


class Connection:
    """Живое соединение к одному серверу. Потокобезопасно на уровне paramiko."""

    def __init__(self, profile: ServerProfile, client: paramiko.SSHClient,
                 host_key: dict | None = None):
        self.profile = profile
        self.host_key = host_key or {}
        self._client = client
        self._sftp: paramiko.SFTPClient | None = None
        self._sftp_lock = threading.Lock()

    # ------------------------------------------------------------- состояние

    @property
    def client(self) -> paramiko.SSHClient:
        return self._client

    @property
    def transport(self) -> paramiko.Transport | None:
        return self._client.get_transport()

    def alive(self) -> bool:
        transport = self.transport
        return transport is not None and transport.is_active()

    # -------------------------------------------------------------- команды

    def run(self, cmd: str, *, check: bool = False,
            timeout: int = DEFAULT_CMD_TIMEOUT, stdin: str | None = None,
            max_output: int = 0) -> Result:
        """Выполнить команду и дождаться завершения. См. заметку в шапке модуля."""
        transport = self.transport
        if transport is None or not transport.is_active():
            raise RemoteError(self.profile.name, cmd, -1, "", "транспорт неактивен")

        chan = transport.open_session(timeout=timeout)
        chan.settimeout(timeout)
        chan.exec_command(cmd)

        if stdin is not None:
            with chan.makefile("wb") as handle:
                handle.write(stdin.encode("utf-8"))
            chan.shutdown_write()

        deadline = time.monotonic() + timeout
        out, err = bytearray(), bytearray()
        truncated = False
        while True:
            moved = False
            if chan.recv_ready():
                out += chan.recv(65536)
                moved = True
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
                moved = True

            if max_output and len(out) > max_output and not truncated:
                # Вывод уже не влезет в ответ агенту: перестаём копить, но
                # продолжаем вычёрпывать канал, иначе удалённая команда встанет.
                truncated = True
            if truncated:
                del out[max_output:]

            if (chan.exit_status_ready()
                    and not chan.recv_ready()
                    and not chan.recv_stderr_ready()):
                break

            if time.monotonic() > deadline:
                chan.close()
                raise RemoteError(
                    self.profile.name, cmd, -1,
                    out.decode("utf-8", "replace"),
                    f"превышен таймаут {timeout} с — команда не завершилась",
                )

            if not moved:
                time.sleep(POLL_INTERVAL)

        rc = chan.recv_exit_status()
        chan.close()

        result = Result(
            rc,
            out.decode("utf-8", "replace"),
            err.decode("utf-8", "replace"),
            truncated=truncated,
        )
        if check and not result.ok:
            raise RemoteError(self.profile.name, cmd, rc, result.stdout, result.stderr)
        return result

    def exists(self, remote_path: str) -> bool:
        return self.run(f"test -e {shlex.quote(remote_path)}", timeout=30).ok

    def read(self, remote_path: str) -> str | None:
        result = self.run(f"cat {shlex.quote(remote_path)}", timeout=60)
        return result.stdout if result.ok else None

    # ----------------------------------------------------------------- файлы

    @property
    def sftp(self) -> paramiko.SFTPClient:
        with self._sftp_lock:
            if self._sftp is None:
                self._sftp = self._client.open_sftp()
            return self._sftp

    def deploy(self, content: str, remote_path: str, *, mode: str = "0644",
               owner: str | None = None, validate: str | None = None,
               backup: bool = True) -> dict:
        """
        Идемпотентно положить файл.

        Порядок намеренный: сравнить хеш → залить во временный → проверить
        временный → атомарно переставить. На месте боевого файла никогда не
        оказывается непроверенное содержимое, а наполовину записанный конфиг
        не роняет сервис при перезагрузке.

        ``validate`` — шаблон команды с ``{}`` вместо пути, например
        ``"nginx -t -c {}"`` или ``"nft -c -f {}"``.
        """
        data = content.encode("utf-8")
        want = hashlib.sha256(data).hexdigest()

        current = self.run(
            f"sha256sum {shlex.quote(remote_path)} 2>/dev/null | cut -d' ' -f1",
            timeout=60,
        ).out
        if current == want:
            return {"changed": False, "reason": "содержимое совпадает", "sha256": want}

        tmp = f"{remote_path}{_TMP_SUFFIX}"
        with self.sftp.open(tmp, "wb") as handle:
            handle.write(data)

        try:
            if validate:
                self.run(validate.format(shlex.quote(tmp)), check=True, timeout=120)

            q_tmp, q_dst = shlex.quote(tmp), shlex.quote(remote_path)
            steps = []
            if owner:
                steps.append(f"chown {shlex.quote(owner)} {q_tmp}")
            steps.append(f"chmod {mode} {q_tmp}")
            if backup:
                steps.append(f"cp -a {q_dst} {q_dst}.bak 2>/dev/null || true")
            steps.append(f"mv -f {q_tmp} {q_dst}")  # rename(2) — атомарен
            self.run(" && ".join(steps), check=True, timeout=60)
        except Exception:
            self.run(f"rm -f {shlex.quote(tmp)}", timeout=30)
            raise

        return {
            "changed": True,
            "reason": "создан" if not current else "содержимое отличалось",
            "sha256": want,
            "validated": bool(validate),
            "backup": backup and bool(current),
        }

    def close(self) -> None:
        with self._sftp_lock:
            if self._sftp is not None:
                try:
                    self._sftp.close()
                except Exception:
                    pass
                self._sftp = None
        self._client.close()
