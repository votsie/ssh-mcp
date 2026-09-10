"""
Реестр живого состояния процесса: соединения, PTY-сессии, туннели.

MCP-сервер — ровно один процесс на всю сессию Claude Code, поэтому обычный
словарь уровня модуля и есть механизм, благодаря которому открытая сессия
переживает отдельный вызов тула. Ничего не сериализуется: перезапуск сервера
теряет сессии и туннели, и это правильное поведение — оболочка на той стороне
всё равно уже мертва вместе со своим ``cd``, окружением и открытым редактором.

Блокировка держится только на время работы со словарями и никогда — на время
сетевого ввода-вывода.
"""

from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import store
from .config import SHELL_TTL, log
from .connection import Connection, connect
from .store import ServerProfile


class UnknownServer(KeyError):
    """Сервер не найден ни в хранилище, ни среди живых соединений."""


@dataclass
class Handle:
    """Соединение вместе с временными метками."""

    connection: Connection
    opened_at: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    saved: bool = True

    def touch(self) -> None:
        self.last_used = time.monotonic()


_lock = threading.RLock()
_conns: dict[str, Handle] = {}
_sessions: dict[str, object] = {}
_tunnels: dict[str, object] = {}
_pending: dict[str, ServerProfile] = {}

_session_ids = itertools.count(1)
_tunnel_ids = itertools.count(1)
_pending_ids = itertools.count(1)

_janitor: threading.Thread | None = None
_stop = threading.Event()


# ------------------------------------------------------------- соединения


def _jump_channel(profile: ServerProfile, chain: tuple[str, ...]):
    """
    Открыть канал до сервера через прыжковый хост.

    Нужно там, где сервер закрыт фаерволом снаружи и виден только из своей же
    сети. Проверка ключа хоста при этом не ослабевает: сверяется ключ конечного
    сервера, а не промежуточного.
    """
    jump = profile.jump.strip().lower()
    if jump in chain:
        raise UnknownServer(
            f"кольцо прыжковых хостов: {' -> '.join((*chain, jump))}"
        )
    hop = acquire(jump, chain=(*chain, profile.name.lower()))
    transport = hop.connection.transport
    if transport is None or not transport.is_active():
        raise UnknownServer(f"прыжковый хост {jump!r} недоступен")
    log.info("иду к %s через %s", profile.name, jump)
    return transport.open_channel(
        "direct-tcpip", (profile.host, profile.port), ("127.0.0.1", 0)
    )


def _open(profile: ServerProfile, saved: bool,
          chain: tuple[str, ...] = ()) -> Handle:
    sock = _jump_channel(profile, chain) if profile.jump else None
    client, report = connect(profile, sock=sock)
    if profile.jump:
        report["via"] = profile.jump
    handle = Handle(Connection(profile, client, report), saved=saved)
    with _lock:
        _conns[profile.name.lower()] = handle
    return handle


def acquire(name: str, *, reconnect: bool = True,
            chain: tuple[str, ...] = ()) -> Handle:
    """
    Взять живое соединение по имени, при необходимости переподключившись.

    Переиспользование существенно: открыть канал на живом транспорте стоит
    миллисекунды, а новое соединение — секунду с лишним на TCP и обмен ключами.
    """
    key = name.strip().lower()
    with _lock:
        handle = _conns.get(key)

    if handle is not None and handle.connection.alive():
        handle.touch()
        return handle

    if handle is not None:
        log.info("соединение с %s разорвано, переподключаюсь", key)
        with _lock:
            _conns.pop(key, None)
        try:
            handle.connection.close()
        except Exception:
            pass
        if not reconnect:
            raise UnknownServer(key)
        profile = handle.connection.profile
    else:
        profile = store.get(key)
        if profile is None:
            raise UnknownServer(
                f"сервер {name!r} неизвестен. Посмотрите ssh_status() или "
                f"подключитесь, передав host/user/password"
            )

    handle = _open(profile, saved=store.get(key) is not None, chain=chain)
    return handle


def adopt(profile: ServerProfile, handle_key: str | None = None) -> str:
    """
    Поместить в реестр соединение к ещё не сохранённому серверу.

    Возвращает временный идентификатор. Он нужен, чтобы после того, как
    человек назовёт сервер, можно было сохранить профиль и не переподключаться.
    """
    pending_id = handle_key or f"unsaved:{next(_pending_ids):02d}"
    handle = _open(profile, saved=False)
    with _lock:
        _conns.pop(profile.name.lower(), None)
        _conns[pending_id] = handle
        _pending[pending_id] = profile
    return pending_id


def pending_profile(pending_id: str) -> ServerProfile | None:
    with _lock:
        return _pending.get(pending_id)


def rename(pending_id: str, name: str) -> None:
    """Переименовать временное соединение в постоянное после сохранения."""
    key = name.strip().lower()
    with _lock:
        handle = _conns.pop(pending_id, None)
        _pending.pop(pending_id, None)
        if handle is None:
            return
        handle.saved = True
        _conns[key] = handle


def resolve(target: str) -> Handle:
    """Принять как имя сохранённого сервера, так и временный идентификатор."""
    with _lock:
        handle = _conns.get(target)
    if handle is not None and handle.connection.alive():
        handle.touch()
        return handle
    return acquire(target)


def drop(name: str) -> bool:
    """Закрыть соединение вместе со всеми его сессиями и туннелями."""
    key = name.strip().lower()
    with _lock:
        handle = _conns.pop(key, None) or _conns.pop(name, None)
        _pending.pop(name, None)
        victims = [s for s in _sessions.values() if getattr(s, "server", None) == key]
        tunnels = [t for t in _tunnels.values() if getattr(t, "server", None) == key]
    for item in victims + tunnels:
        _safe_close(item)
    if handle is None:
        return False
    _safe_close(handle.connection)
    return True


def connections() -> list[dict]:
    with _lock:
        items = list(_conns.items())
    now = time.monotonic()
    return [
        {
            "name": key,
            "endpoint": handle.connection.profile.endpoint,
            "alive": handle.connection.alive(),
            "saved": handle.saved,
            "idle_s": round(now - handle.last_used, 1),
        }
        for key, handle in items
    ]


# ------------------------------------------- сессии и туннели (общий реестр)


def add_session(session) -> str:
    session_id = f"s{next(_session_ids)}"
    session.id = session_id
    with _lock:
        _sessions[session_id] = session
    return session_id


def get_session(session_id: str):
    with _lock:
        session = _sessions.get(session_id)
    if session is None:
        raise KeyError(
            f"сессия {session_id!r} не найдена. Возможно, её закрыл сборщик "
            f"после простоя — откройте новую через ssh_shell_open"
        )
    return session


def remove_session(session_id: str) -> bool:
    with _lock:
        session = _sessions.pop(session_id, None)
    if session is None:
        return False
    _safe_close(session)
    return True


def sessions() -> list:
    with _lock:
        return list(_sessions.values())


def add_tunnel(tunnel) -> str:
    tunnel_id = f"t{next(_tunnel_ids)}"
    tunnel.id = tunnel_id
    with _lock:
        _tunnels[tunnel_id] = tunnel
    return tunnel_id


def get_tunnel(tunnel_id: str):
    with _lock:
        tunnel = _tunnels.get(tunnel_id)
    if tunnel is None:
        raise KeyError(f"туннель {tunnel_id!r} не найден")
    return tunnel


def remove_tunnel(tunnel_id: str) -> bool:
    with _lock:
        tunnel = _tunnels.pop(tunnel_id, None)
    if tunnel is None:
        return False
    _safe_close(tunnel)
    return True


def tunnels() -> list:
    with _lock:
        return list(_tunnels.values())


# ------------------------------------------------------- уборка и остановка


def _safe_close(item) -> None:
    closer: Callable | None = getattr(item, "close", None)
    if closer is None:
        return
    try:
        closer()
    except Exception as exc:
        log.warning("не закрылось %r: %s", item, exc)


def _janitor_loop() -> None:
    """
    Сборщик простаивающих сессий: агент регулярно забывает их закрывать.

    Туннели не трогаем никогда — это явно заказанная инфраструктура, и её
    исчезновение по таймеру было бы сюрпризом в самый неподходящий момент.
    """
    while not _stop.wait(30):
        now = time.monotonic()
        expired = []
        with _lock:
            for session_id, session in list(_sessions.items()):
                idle = now - getattr(session, "last_used", now)
                dead = not getattr(session, "alive", lambda: True)()
                if idle > SHELL_TTL or dead:
                    expired.append((session_id, "простой" if idle > SHELL_TTL else "канал закрыт"))
        for session_id, reason in expired:
            log.info("закрываю сессию %s: %s", session_id, reason)
            remove_session(session_id)


def start_janitor() -> None:
    global _janitor
    if _janitor is None or not _janitor.is_alive():
        _stop.clear()
        _janitor = threading.Thread(target=_janitor_loop, name="ssh-mcp-janitor", daemon=True)
        _janitor.start()


def shutdown() -> None:
    """
    Закрыть всё в правильном порядке: туннели, сессии, соединения.

    Сначала туннели — у удалённого проброса на стороне sshd остаётся
    слушающий сокет, и его надо снять до того, как исчезнет транспорт.
    """
    _stop.set()
    with _lock:
        tunnel_list = list(_tunnels.values())
        session_list = list(_sessions.values())
        conn_list = [handle.connection for handle in _conns.values()]
        _tunnels.clear()
        _sessions.clear()
        _conns.clear()
        _pending.clear()
    for item in tunnel_list + session_list + conn_list:
        _safe_close(item)
    log.info(
        "остановка: закрыто туннелей=%d сессий=%d соединений=%d",
        len(tunnel_list), len(session_list), len(conn_list),
    )
