"""
Пути, настройки и логирование.

Всё состояние живёт в одном каталоге вне репозиториев (по умолчанию
``~/.ssh-mcp``), чтобы файл с паролями физически не мог попасть в git.
Переопределяется переменной ``SSHM_HOME``.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _home() -> Path:
    override = os.environ.get("SSHM_HOME")
    return Path(override).expanduser() if override else Path.home() / ".ssh-mcp"


HOME = _home()
SERVERS_ENV = HOME / "servers.env"
KNOWN_HOSTS = HOME / "known_hosts"
MEMORY_DIR = HOME / "memory"
HISTORY_FILE = HOME / "history.jsonl"
LOG_FILE = HOME / "logs" / "ssh-mcp.log"

USER_KNOWN_HOSTS = Path.home() / ".ssh" / "known_hosts"


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


CONNECT_TIMEOUT = _int_env("SSHM_CONNECT_TIMEOUT", 20)
DEFAULT_CMD_TIMEOUT = _int_env("SSHM_CMD_TIMEOUT", 300)
SHELL_TTL = _int_env("SSHM_SHELL_TTL", 1800)
KEEPALIVE = _int_env("SSHM_KEEPALIVE", 30)
HISTORY_MAX_BYTES = _int_env("SSHM_HISTORY_MAX_BYTES", 5 * 1024 * 1024)

POLL_INTERVAL = 0.05  # пауза между опросами канала, когда данных нет

log = logging.getLogger("ssh_mcp")


def ensure_home() -> None:
    """Создать каталог состояния. 0700, чтобы прочитать мог только владелец."""
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    MEMORY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    LOG_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    harden_permissions(HOME)


def fix_console_encoding() -> None:
    """
    Windows по умолчанию отдаёт cp1251, и кириллица в диагностике ломается.

    Трогаем ТОЛЬКО stderr. ``sys.stdout`` — это транспорт JSON-RPC, которым
    владеет MCP SDK: любая его перенастройка (как и единственный ``print``)
    рвёт кадрирование протокола, а хост показывает загадочное «server
    disconnected».
    """
    reconfigure = getattr(sys.stderr, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def harden_permissions(path: Path) -> None:
    """
    Ограничить доступ к файлу или каталогу владельцем.

    ``chmod`` на NTFS выставляет только атрибут «только для чтения» и никому
    ничего не запрещает — сам по себе это защитная бутафория. На Windows
    реальный контроль даёт ``icacls``: снимаем наследование и оставляем
    единственную ACE на текущего пользователя.
    """
    try:
        path.chmod(0o700 if path.is_dir() else 0o600)
    except OSError:
        pass

    if os.name != "nt":
        return

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("icacls не отработал для %s: %s", path, exc)


def setup_logging() -> None:
    """
    Лог только в файл. Писать в stdout нельзя — там протокол MCP; stderr
    засоряет транскрипт хоста, поэтому туда уходят лишь аварии.
    """
    ensure_home()
    if log.handlers:
        return
    log.setLevel(logging.DEBUG if os.environ.get("SSHM_DEBUG") else logging.INFO)
    handler = RotatingFileHandler(
        LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=2, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    log.addHandler(handler)
    log.propagate = False
