"""
Проброс портов: локальный, удалённый и динамический SOCKS5.

Слушатели живут в фоновых потоках и потому переживают отдельный вызов тула.
Все потоки — демоны, так что вместе с процессом MCP туннели гарантированно
исчезают и после выхода Claude Code брошенных слушателей не остаётся.
"""

from __future__ import annotations

import select
import socket
import socketserver
import threading
import time

from .config import log

PUMP_CHUNK = 32768
SELECT_TIMEOUT = 1.0


class TunnelError(RuntimeError):
    """Не удалось поднять или удержать проброс."""


def _pump(sock: socket.socket, channel, stats: dict) -> None:
    """
    Перекачка в обе стороны.

    Через select, а не двумя блокирующими потоками на соединение: у paramiko
    ``Channel.fileno()`` подложен сокетной парой ровно затем, чтобы select
    работал в том числе на Windows.
    """
    try:
        while True:
            ready, _, _ = select.select([sock, channel], [], [], SELECT_TIMEOUT)
            if sock in ready:
                data = sock.recv(PUMP_CHUNK)
                if not data:
                    break
                channel.sendall(data)
                stats["bytes_out"] += len(data)
            if channel in ready:
                data = channel.recv(PUMP_CHUNK)
                if not data:
                    break
                sock.sendall(data)
                stats["bytes_in"] += len(data)
            if channel.exit_status_ready() and not channel.recv_ready():
                break
    except (OSError, EOFError):
        pass
    finally:
        for closeable in (channel, sock):
            try:
                closeable.close()
            except Exception:
                pass


class _Tunnel:
    """Общая часть: идентификатор, счётчики, описание для ssh_status."""

    kind = "base"

    def __init__(self, server: str):
        self.id = ""
        self.server = server
        self.opened_at = time.monotonic()
        self.stats = {"conns": 0, "bytes_in": 0, "bytes_out": 0}
        self.last_error: str | None = None
        self.bound_host = ""
        self.bound_port = 0
        self._closed = False

    def describe(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "server": self.server,
            "bound": f"{self.bound_host}:{self.bound_port}",
            "alive": not self._closed,
            "age_s": round(time.monotonic() - self.opened_at, 1),
            **self.stats,
            **({"last_error": self.last_error} if self.last_error else {}),
        }


class _ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    # SO_REUSEADDR на Windows разрешает перехватить ЖИВОГО слушателя, а не
    # просто переиспользовать порт в TIME_WAIT. Молча увести чужой трафик
    # хуже, чем честно упасть с «порт занят».
    allow_reuse_address = False


class LocalTunnel(_Tunnel):
    """Локальный проброс: порт на этой машине → адрес, видимый с сервера."""

    kind = "local"

    def __init__(self, server: str, transport, dest_host: str, dest_port: int,
                 listen_port: int = 0, bind: str = "127.0.0.1"):
        super().__init__(server)
        self.transport = transport
        self.dest = (dest_host, dest_port)
        tunnel = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self_inner):
                tunnel.stats["conns"] += 1
                try:
                    channel = tunnel.transport.open_channel(
                        "direct-tcpip", tunnel.dest, self_inner.request.getpeername()
                    )
                except Exception as exc:
                    tunnel.last_error = str(exc)
                    log.warning("туннель %s: канал не открылся: %s", tunnel.id, exc)
                    return
                _pump(self_inner.request, channel, tunnel.stats)

        try:
            self._server = _ForwardServer((bind, listen_port), Handler)
        except OSError as exc:
            raise TunnelError(
                f"не удалось занять {bind}:{listen_port} — {exc}. "
                f"Не указывайте listen_port, и порт выберет система"
            ) from exc

        self.bound_host, self.bound_port = self._server.server_address[:2]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._closed = True
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass


class RemoteTunnel(_Tunnel):
    """Удалённый проброс: порт на сервере → адрес, видимый с этой машины."""

    kind = "remote"

    def __init__(self, server: str, transport, dest_host: str, dest_port: int,
                 remote_port: int = 0, remote_bind: str = ""):
        super().__init__(server)
        self.transport = transport
        self.dest = (dest_host, dest_port)

        def handler(channel, origin, destination):
            self.stats["conns"] += 1
            try:
                sock = socket.create_connection(self.dest, timeout=10)
            except OSError as exc:
                self.last_error = str(exc)
                channel.close()
                return
            threading.Thread(
                target=_pump, args=(sock, channel, self.stats), daemon=True
            ).start()

        try:
            self.bound_port = transport.request_port_forward(
                address=remote_bind, port=remote_port, handler=handler
            )
        except Exception as exc:
            raise TunnelError(f"сервер отказал в удалённом пробросе: {exc}") from exc
        self.bound_host = remote_bind or "127.0.0.1"
        self._remote_bind = remote_bind

    def describe(self) -> dict:
        info = super().describe()
        info["note"] = (
            "Слушает на стороне сервера. Адрес шире 127.0.0.1 получится только "
            "при GatewayPorts yes в sshd_config — иначе sshd молча сузит его "
            "до петли."
        )
        return info

    def close(self) -> None:
        self._closed = True
        try:
            # Снять слушателя на стороне sshd обязательно: иначе он висит,
            # пока не оборвётся всё соединение.
            self.transport.cancel_port_forward(self._remote_bind, self.bound_port)
        except Exception:
            pass


class DynamicTunnel(_Tunnel):
    """Динамический проброс: локальный SOCKS5-прокси в сеть сервера."""

    kind = "dynamic"

    def __init__(self, server: str, transport, listen_port: int = 0,
                 bind: str = "127.0.0.1"):
        super().__init__(server)
        self.transport = transport
        tunnel = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self_inner):
                sock = self_inner.request
                try:
                    destination = _socks5_handshake(sock)
                except Exception as exc:
                    tunnel.last_error = str(exc)
                    sock.close()
                    return
                if destination is None:
                    sock.close()
                    return

                tunnel.stats["conns"] += 1
                try:
                    channel = tunnel.transport.open_channel(
                        "direct-tcpip", destination, sock.getpeername()
                    )
                except Exception as exc:
                    tunnel.last_error = str(exc)
                    # 0x05 — connection refused: клиент должен упасть сразу,
                    # а не ждать таймаута.
                    _socks5_reply(sock, 0x05)
                    sock.close()
                    return
                _socks5_reply(sock, 0x00)
                _pump(sock, channel, tunnel.stats)

        try:
            self._server = _ForwardServer((bind, listen_port), Handler)
        except OSError as exc:
            raise TunnelError(
                f"не удалось занять {bind}:{listen_port} — {exc}. "
                f"Не указывайте listen_port, и порт выберет система"
            ) from exc

        self.bound_host, self.bound_port = self._server.server_address[:2]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._closed = True
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("клиент закрыл соединение на этапе SOCKS5")
        data += chunk
    return data


def _socks5_reply(sock: socket.socket, code: int) -> None:
    sock.sendall(bytes([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))


def _socks5_handshake(sock: socket.socket) -> tuple[str, int] | None:
    """
    Разобрать запрос SOCKS5 и вернуть адрес назначения.

    Аутентификации нет намеренно: слушаем только на петле. Доменное имя
    передаём дальше НЕразрешённым — в этом весь смысл, DNS должен резолвиться
    на стороне сервера (``socks5h://``).
    """
    version, n_methods = _recv_exact(sock, 2)
    if version != 0x05:
        raise ValueError(f"не SOCKS5, версия {version}")
    _recv_exact(sock, n_methods)
    sock.sendall(bytes([0x05, 0x00]))  # без аутентификации

    version, command, _, address_type = _recv_exact(sock, 4)
    if version != 0x05:
        raise ValueError("испорченный запрос SOCKS5")
    if command != 0x01:  # только CONNECT; BIND и UDP не поддерживаем
        _socks5_reply(sock, 0x07)
        return None

    if address_type == 0x01:
        host = socket.inet_ntoa(_recv_exact(sock, 4))
    elif address_type == 0x03:
        length = _recv_exact(sock, 1)[0]
        # Не "idna": этот кодек не принимает никакой обработки ошибок, кроме
        # strict, и на любом имени бросал бы исключение. В SOCKS5 имя и так
        # приходит уже в ASCII-совместимом виде.
        host = _recv_exact(sock, length).decode("utf-8", "replace")
    elif address_type == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    else:
        _socks5_reply(sock, 0x08)
        return None

    port = int.from_bytes(_recv_exact(sock, 2), "big")
    return host, port
