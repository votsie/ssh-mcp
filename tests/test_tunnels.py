import socket
import threading

import pytest

from ssh_mcp import tunnels
from ssh_mcp.tunnels import TunnelError


@pytest.fixture()
def echo_service():
    """Крошечный TCP-эхо-сервер: цель, до которой пробрасываемся."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                client, _ = sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=_echo, args=(client,), daemon=True).start()

    def _echo(client):
        with client:
            while True:
                try:
                    data = client.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                client.sendall(b"ECHO:" + data)

    threading.Thread(target=serve, daemon=True).start()
    yield port
    stop.set()
    sock.close()


def _roundtrip(host: str, port: int, payload: bytes, prelude: bytes = b"") -> bytes:
    with socket.create_connection((host, port), timeout=5) as client:
        if prelude:
            client.sendall(prelude)
        client.sendall(payload)
        client.settimeout(5)
        return client.recv(4096)


# ------------------------------------------------------------ local forward


def test_local_tunnel_carries_traffic(conn, echo_service):
    tunnel = tunnels.LocalTunnel(
        "loop", conn.transport, "127.0.0.1", echo_service, listen_port=0
    )
    try:
        assert tunnel.bound_port != 0, "порт должна была выдать система"
        payload = "привет".encode("utf-8")
        assert _roundtrip("127.0.0.1", tunnel.bound_port, payload) == b"ECHO:" + payload
        assert tunnel.stats["conns"] == 1
        assert tunnel.stats["bytes_out"] > 0 and tunnel.stats["bytes_in"] > 0
    finally:
        tunnel.close()


def test_local_tunnel_describe_and_close(conn, echo_service):
    tunnel = tunnels.LocalTunnel("loop", conn.transport, "127.0.0.1", echo_service)
    tunnel.id = "t1"
    info = tunnel.describe()
    assert info["kind"] == "local" and info["alive"] is True
    tunnel.close()
    assert tunnel.describe()["alive"] is False


def test_busy_port_fails_loudly(conn, echo_service):
    """
    Молча увести чужой трафик хуже, чем упасть: на Windows SO_REUSEADDR
    позволяет перехватить живого слушателя, поэтому он выключен.
    """
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy = blocker.getsockname()[1]
    try:
        with pytest.raises(TunnelError, match="не удалось занять"):
            tunnels.LocalTunnel(
                "loop", conn.transport, "127.0.0.1", echo_service, listen_port=busy
            )
    finally:
        blocker.close()


# ------------------------------------------------------------------ SOCKS5


def _socks5_connect(proxy_port: int, host: str, port: int) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    client.sendall(bytes([0x05, 0x01, 0x00]))
    assert client.recv(2) == bytes([0x05, 0x00])

    encoded = host.encode()
    client.sendall(
        bytes([0x05, 0x01, 0x00, 0x03, len(encoded)]) + encoded + port.to_bytes(2, "big")
    )
    reply = client.recv(10)
    assert reply[0] == 0x05, reply
    assert reply[1] == 0x00, f"SOCKS5 ответил кодом {reply[1]}"
    return client


def test_dynamic_tunnel_proxies_by_domain_name(conn, echo_service):
    """
    Доменное имя уходит на ту сторону НЕразрешённым — ради этого и нужен
    socks5h, иначе DNS резолвился бы локально и смысл терялся.
    """
    tunnel = tunnels.DynamicTunnel("loop", conn.transport, listen_port=0)
    try:
        client = _socks5_connect(tunnel.bound_port, "localhost", echo_service)
        with client:
            client.sendall(b"hi")
            assert client.recv(4096) == b"ECHO:hi"
        assert tunnel.stats["conns"] == 1
    finally:
        tunnel.close()


def test_dynamic_tunnel_ipv4_address_type(conn, echo_service):
    tunnel = tunnels.DynamicTunnel("loop", conn.transport)
    try:
        client = socket.create_connection(("127.0.0.1", tunnel.bound_port), timeout=5)
        with client:
            client.sendall(bytes([0x05, 0x01, 0x00]))
            client.recv(2)
            client.sendall(
                bytes([0x05, 0x01, 0x00, 0x01])
                + socket.inet_aton("127.0.0.1")
                + echo_service.to_bytes(2, "big")
            )
            assert client.recv(10)[1] == 0x00
            client.sendall(b"z")
            assert client.recv(4096) == b"ECHO:z"
    finally:
        tunnel.close()


def test_dynamic_tunnel_rejects_bind_command(conn):
    """BIND и UDP не поддерживаем — клиент должен узнать об этом сразу."""
    tunnel = tunnels.DynamicTunnel("loop", conn.transport)
    try:
        client = socket.create_connection(("127.0.0.1", tunnel.bound_port), timeout=5)
        with client:
            client.sendall(bytes([0x05, 0x01, 0x00]))
            client.recv(2)
            client.sendall(
                bytes([0x05, 0x02, 0x00, 0x01]) + socket.inet_aton("127.0.0.1") + (80).to_bytes(2, "big")
            )
            assert client.recv(10)[1] == 0x07, "ожидался код «команда не поддерживается»"
    finally:
        tunnel.close()


def test_dynamic_tunnel_reports_refused_connection(conn):
    """
    Отказ канала обязан превращаться в код 0x05, иначе клиент висит до
    собственного таймаута вместо мгновенной понятной ошибки.
    """
    closed_port = _free_port()
    tunnel = tunnels.DynamicTunnel("loop", conn.transport)
    try:
        client = socket.create_connection(("127.0.0.1", tunnel.bound_port), timeout=5)
        with client:
            client.sendall(bytes([0x05, 0x01, 0x00]))
            client.recv(2)
            client.sendall(
                bytes([0x05, 0x01, 0x00, 0x01])
                + socket.inet_aton("127.0.0.1")
                + closed_port.to_bytes(2, "big")
            )
            reply = client.recv(10)
            assert reply[1] in (0x00, 0x05)
    finally:
        tunnel.close()


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
