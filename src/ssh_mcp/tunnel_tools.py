"""Инструменты проброса портов."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from . import memory, registry, tunnels
from .server import _fail, mcp

_KINDS = ("local", "remote", "dynamic")


@mcp.tool()
def ssh_tunnel_open(
    server: str,
    kind: Annotated[str, Field(
        description="local — порт здесь ведёт в сеть сервера; remote — порт на "
                    "сервере ведёт сюда; dynamic — SOCKS5-прокси в сеть сервера"
    )] = "local",
    listen_port: Annotated[int, Field(
        description="0 — порт выберет система, и это правильный выбор по умолчанию"
    )] = 0,
    dest_host: str | None = None,
    dest_port: int | None = None,
    bind: str = "127.0.0.1",
) -> dict:
    """
    Поднять туннель до сервера.

    Панель, слушающую на 127.0.0.1:2053, открывают как kind='local' с
    dest_host='127.0.0.1', dest_port=2053 — и она становится доступна по
    возвращённому адресу. Туннель живёт до конца сессии Claude Code.
    """
    if kind not in _KINDS:
        raise _fail(f"kind должен быть одним из {_KINDS}")

    handle = registry.resolve(server)
    transport = handle.connection.transport
    if transport is None:
        raise _fail(f"нет живого транспорта до {server}")

    try:
        if kind == "dynamic":
            tunnel = tunnels.DynamicTunnel(server, transport, listen_port, bind)
        else:
            if not dest_host or not dest_port:
                raise _fail(f"для kind={kind} нужны dest_host и dest_port")
            if kind == "local":
                tunnel = tunnels.LocalTunnel(
                    server, transport, dest_host, dest_port, listen_port, bind
                )
            else:
                tunnel = tunnels.RemoteTunnel(
                    server, transport, dest_host, dest_port, listen_port
                )
    except tunnels.TunnelError as exc:
        raise _fail(str(exc)) from exc

    tunnel_id = registry.add_tunnel(tunnel)
    memory.record("ssh_tunnel_open", server, kind=kind, bound=tunnel.bound_port)

    result = tunnel.describe()
    if kind == "dynamic":
        result["url_hint"] = (
            f"socks5h://{tunnel.bound_host}:{tunnel.bound_port} — именно socks5h, "
            f"чтобы DNS резолвился на стороне сервера"
        )
    elif kind == "local":
        result["url_hint"] = f"http://{tunnel.bound_host}:{tunnel.bound_port}"
    result["lifetime"] = "до перезапуска MCP, то есть до конца сессии Claude Code"
    return result


@mcp.tool()
def ssh_tunnel_close(tunnel_id: str | None = None) -> dict:
    """Закрыть туннель. Без аргумента закрывает все."""
    if tunnel_id:
        return {"closed": [tunnel_id] if registry.remove_tunnel(tunnel_id) else []}
    ids = [tunnel.id for tunnel in registry.tunnels()]
    for item in ids:
        registry.remove_tunnel(item)
    return {"closed": ids}
