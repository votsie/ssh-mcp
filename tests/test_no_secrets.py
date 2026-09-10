"""
Сторож против утечки секретов в открытый репозиторий.

Написан после того, как боевые пароли шести серверов и парольная фраза от
приватного ключа едва не уехали в публичный git. Открытый репозиторий — это
навсегда: удаление файла не удаляет его из истории, а секрет надо считать
скомпрометированным с момента публикации.

Проверяется не наличие конкретных известных строк, а формы, в которых секрет
обычно и попадает в код.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {".py", ".md", ".toml", ".json", ".txt", ".cfg", ".yml", ".yaml"}

# Адреса, отведённые под документацию (RFC 5737, RFC 3849) и петля —
# единственные, которым место в открытом коде.
_ALLOWED_NETS = (
    "192.0.2.", "198.51.100.", "203.0.113.",   # RFC 5737, для документации
    "127.0.0.", "0.0.0.0", "255.255.255.",
    "10.", "192.168.", "172.16.", "172.17.",   # частные сети
    "1.2.3.4",
)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Именно блок целиком: одно упоминание заголовка в тесте — не ключ.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.{40,}?-----END [A-Z ]*PRIVATE KEY-----",
    re.S,
)

# Признаки настоящего приватного ключа PuTTY: файл с ним в репозитории
# недопустим ни при каких условиях.
_PPK = re.compile(r"^PuTTY-User-Key-File-\d.*^Private-MAC:", re.M | re.S)


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    return [ROOT / line for line in out.stdout.splitlines() if line.strip()]


def text_files() -> list[Path]:
    return [
        path for path in tracked_files()
        if path.suffix.lower() in TEXT_SUFFIXES and path.exists()
    ]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def test_no_private_key_material() -> None:
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in tracked_files()
        if path.exists() and path.suffix.lower() in TEXT_SUFFIXES | {".ppk", ".pem", ".key"}
        and (_PRIVATE_KEY.search(_read(path)) or _PPK.search(_read(path)))
    ]
    assert not offenders, f"приватный ключ в репозитории: {offenders}"


def test_no_routable_ip_addresses() -> None:
    """
    Боевой адрес в коде — это и наводка на инфраструктуру, и почти всегда
    признак, что рядом лежат доступы к ней.
    """
    offenders: list[str] = []
    for path in text_files():
        if path.name == "test_no_secrets.py":
            continue
        for number, line in enumerate(_read(path).splitlines(), 1):
            for address in _IPV4.findall(line):
                if any(address.startswith(net) for net in _ALLOWED_NETS):
                    continue
                if all(part.isdigit() and int(part) < 256 for part in address.split(".")):
                    offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number} {address}")
    assert not offenders, "боевые адреса: " + "; ".join(offenders)


def test_no_real_home_directories() -> None:
    """Путь вида C:\\Users\\<имя> выдаёт машину и ломает тесты у всех остальных."""
    pattern = re.compile(r"[Cc]:[\\/]Users[\\/](?!<)[A-Za-zА-Яа-я0-9_.-]+")
    offenders: list[str] = []
    for path in text_files():
        if path.name == "test_no_secrets.py":
            continue
        for number, line in enumerate(_read(path).splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    assert not offenders, "пути к личным каталогам: " + "; ".join(offenders)


def test_real_fixtures_come_from_the_environment() -> None:
    """
    Тесты на настоящих файлах должны включаться переменными окружения, а не
    жёстко зашитыми путями: иначе такой путь однажды приедет вместе с данными.
    """
    for name in ("SSHM_TEST_PPK", "SSHM_TEST_LEGACY_FILE"):
        found = subprocess.run(
            ["git", "grep", "-l", name], cwd=ROOT,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        assert found.stdout.strip(), f"{name} нигде не используется"


@pytest.mark.parametrize("suffix", [".ppk", ".pem", ".key", ".p12", ".pfx"])
def test_no_key_files_tracked(suffix: str) -> None:
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in tracked_files() if path.suffix.lower() == suffix
    ]
    assert not offenders, f"файлы ключей под контролем версий: {offenders}"


def test_gitignore_covers_credential_files() -> None:
    text = _read(ROOT / ".gitignore")
    for pattern in ("*.env", "*.ppk", "*.pem", "*.key"):
        assert pattern in text, f"{pattern} не закрыт .gitignore"


def test_no_personal_email_addresses() -> None:
    """
    Личный адрес в открытом репозитории — регресс приватности.

    GitHub не зря выдаёт noreply-адрес: если человек скрывает почту в
    коммитах, а мы вписали её в манифест плагина, скрытие обесценено.
    Разрешены noreply-адреса и домены для документации.
    """
    pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    allowed = ("noreply", "example.com", "example.org", "localhost")
    offenders: list[str] = []
    for path in text_files():
        if path.name == "test_no_secrets.py":
            continue
        for number, line in enumerate(_read(path).splitlines(), 1):
            for address in pattern.findall(line):
                if any(mark in address for mark in allowed):
                    continue
                offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number} {address}")
    assert not offenders, "личные адреса: " + "; ".join(offenders)
