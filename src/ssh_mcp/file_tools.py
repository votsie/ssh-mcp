"""Инструменты обмена файлами по SFTP."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Annotated

from pydantic import Field

from . import memory, redact, registry
from .server import _fail, fence, mcp

MAX_DOWNLOAD = 50 << 20


def _sha256_local(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_remote(conn, remote_path: str) -> str:
    import shlex

    result = conn.run(
        f"sha256sum {shlex.quote(remote_path)} 2>/dev/null | cut -d' ' -f1",
        timeout=120,
    )
    return result.out


@mcp.tool()
def ssh_upload(
    server: str,
    local_path: str,
    remote_path: str,
    mode: str | None = None,
    mkdir: bool = True,
) -> dict:
    """
    Залить локальный файл на сервер и проверить, что он долетел целым.

    Для содержимого, которое вы сами составили, лучше ssh_file_write — он
    идемпотентен, умеет проверку конфига и делает резервную копию.
    """
    import shlex

    source = Path(local_path).expanduser()
    if not source.is_file():
        raise _fail(f"локальный файл {source} не найден")

    handle = registry.resolve(server)
    conn = handle.connection

    if mkdir:
        parent = os.path.dirname(remote_path)
        if parent:
            conn.run(f"mkdir -p {shlex.quote(parent)}", timeout=30)

    conn.sftp.put(str(source), remote_path)
    if mode:
        conn.run(f"chmod {mode} {shlex.quote(remote_path)}", timeout=30)

    local_hash = _sha256_local(source)
    remote_hash = _sha256_remote(conn, remote_path)
    memory.record("ssh_upload", server, remote_path=remote_path, bytes=source.stat().st_size)
    return {
        "server": server,
        "remote_path": remote_path,
        "bytes": source.stat().st_size,
        "sha256_local": local_hash,
        "sha256_remote": remote_hash,
        "verified": bool(remote_hash) and local_hash == remote_hash,
    }


@mcp.tool()
def ssh_download(
    server: str,
    remote_path: str,
    local_path: str,
    max_bytes: int = MAX_DOWNLOAD,
) -> dict:
    """Скачать файл с сервера на эту машину и сверить контрольную сумму."""
    handle = registry.resolve(server)
    conn = handle.connection

    try:
        info = conn.sftp.stat(remote_path)
    except OSError as exc:
        raise _fail(f"{remote_path} недоступен: {exc}") from exc
    if info.st_size and info.st_size > max_bytes:
        raise _fail(
            f"файл {info.st_size} байт больше предела {max_bytes}. "
            f"Поднимите max_bytes, если это осознанно"
        )

    target = Path(local_path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn.sftp.get(remote_path, str(target))

    local_hash = _sha256_local(target)
    remote_hash = _sha256_remote(conn, remote_path)
    memory.record("ssh_download", server, remote_path=remote_path)
    return {
        "server": server,
        "local_path": str(target),
        "bytes": target.stat().st_size,
        "sha256_local": local_hash,
        "sha256_remote": remote_hash,
        "verified": bool(remote_hash) and local_hash == remote_hash,
    }


@mcp.tool()
def ssh_file_read(
    server: str,
    remote_path: str,
    max_bytes: int = 200_000,
) -> dict:
    """Прочитать текстовый файл с сервера. Большие файлы обрезаются."""
    handle = registry.resolve(server)
    with handle.connection.sftp.open(remote_path, "rb") as remote:
        data = remote.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    text = data[:max_bytes].decode("utf-8", "replace")
    return {
        "server": server,
        "remote_path": remote_path,
        "truncated": truncated,
        "content": fence(redact.scrub(text)),
    }


@mcp.tool()
def ssh_file_write(
    server: str,
    remote_path: str,
    content: str,
    mode: str = "0644",
    owner: str | None = None,
    validate: Annotated[str | None, Field(
        description="Команда проверки со скобками {} вместо пути, например 'nginx -t -c {}'"
    )] = None,
    backup: bool = True,
) -> dict:
    """
    Положить файл на сервер атомарно и идемпотентно.

    Порядок намеренный: сверить хеш, залить во временный, проверить временный,
    переставить через rename. На месте боевого файла никогда не оказывается
    непроверенное содержимое, а повторный вызов с тем же текстом ничего не
    делает и честно сообщает changed=false.
    """
    handle = registry.resolve(server)
    try:
        result = handle.connection.deploy(
            content, remote_path, mode=mode, owner=owner,
            validate=validate, backup=backup,
        )
    except Exception as exc:
        raise _fail(f"не удалось записать {remote_path}: {exc}") from exc
    memory.record("ssh_file_write", server, remote_path=remote_path,
                  changed=result.get("changed"))
    return {"server": server, "remote_path": remote_path, **result}


@mcp.tool()
def ssh_list_dir(server: str, remote_path: str = ".", limit: int = 200) -> dict:
    """Показать содержимое каталога на сервере."""
    handle = registry.resolve(server)
    try:
        entries = handle.connection.sftp.listdir_attr(remote_path)
    except OSError as exc:
        raise _fail(f"{remote_path} недоступен: {exc}") from exc

    items = []
    for entry in sorted(entries, key=lambda e: e.filename)[:limit]:
        items.append({
            "name": entry.filename,
            "dir": stat.S_ISDIR(entry.st_mode or 0),
            "size": entry.st_size,
            "mode": oct(stat.S_IMODE(entry.st_mode or 0)),
            "mtime": entry.st_mtime,
        })
    return {
        "server": server,
        "path": remote_path,
        "entries": items,
        "truncated": len(entries) > limit,
    }


@mcp.tool()
def ssh_copy_between(
    src_server: str,
    src_path: str,
    dst_server: str,
    dst_path: str,
) -> dict:
    """
    Перекинуть файл с одного сервера на другой через эту машину.

    Идёт потоком через локальный временный файл: так не требуется никакого
    доверия между серверами, которого между ними обычно и нет.
    """
    import tempfile

    source = registry.resolve(src_server).connection
    target = registry.resolve(dst_server).connection

    with tempfile.NamedTemporaryFile(delete=False) as spool:
        spool_path = Path(spool.name)
    try:
        source.sftp.get(src_path, str(spool_path))
        target.sftp.put(str(spool_path), dst_path)
        src_hash = _sha256_remote(source, src_path)
        dst_hash = _sha256_remote(target, dst_path)
    finally:
        spool_path.unlink(missing_ok=True)

    memory.record("ssh_copy_between", src_server,
                  to=dst_server, src=src_path, dst=dst_path)
    return {
        "from": {"server": src_server, "path": src_path, "sha256": src_hash},
        "to": {"server": dst_server, "path": dst_path, "sha256": dst_hash},
        "verified": bool(src_hash) and src_hash == dst_hash,
    }
