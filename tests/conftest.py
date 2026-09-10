import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Каталог состояния перенаправляем до первого импорта ssh_mcp.config: пути там
# вычисляются на уровне модуля, и настоящий ~/.ssh-mcp тесты трогать не должны.
os.environ.setdefault("SSHM_HOME", "")

# Проверка на настоящем конфиге полезна, но такому файлу в репозитории не
# место. Путь задаётся снаружи, без него тесты просто пропускаются:
#   SSHM_TEST_LEGACY_FILE=/path/to/servers.env pytest
LEGACY_FILE = Path(os.environ.get("SSHM_TEST_LEGACY_FILE") or "нет-такого-файла")

# ВЫДУМАННЫЕ пароли. Ценность не в значениях, а в форме: решётка, запятые,
# вопросительный знак — символы, на которых ломается наивный .env-парсер.
# Настоящих доступов в этом репозитории нет и быть не должно; за этим следит
# tests/test_no_secrets.py.
TRICKY_PASSWORDS = [
    "aXc#,,Q_31ZmT9",
    "bKmN,PQ4wZF-c2",
    "tRSVfJKLMn?.71",
    "7QpR42vTn8Wy",
    "hJ39kLmNpQrS",
    "zW8t61ufBps3",
]


@pytest.fixture()
def store_path(tmp_path: Path) -> Path:
    return tmp_path / "servers.env"


@pytest.fixture()
def sshd(tmp_path, monkeypatch):
    """Локальный sshd плюс изолированные known_hosts — настоящие не трогаем."""
    from ssh_mcp import hostkeys
    from sshd import LoopbackSSHServer

    monkeypatch.setattr(hostkeys, "KNOWN_HOSTS", tmp_path / "known_hosts")
    monkeypatch.setattr(hostkeys, "USER_KNOWN_HOSTS", tmp_path / "user_known_hosts")
    with LoopbackSSHServer() as server:
        yield server


@pytest.fixture()
def conn(sshd):
    from ssh_mcp import connection
    from ssh_mcp.connection import Connection
    from ssh_mcp.store import ServerProfile
    from sshd import PASSWORD, USER

    profile = ServerProfile(
        name="loop", host="127.0.0.1", port=sshd.port,
        user=USER, password=PASSWORD, auth="password",
    )
    client, report = connection.connect(profile)
    created = Connection(profile, client, report)
    yield created
    created.close()
