"""
Импорт старого блочного ``servers.env`` из старого проекта.

Формат — блоки по пять строк, разделённые пустой строкой::

    RU1 - BGD
    198.51.100.11
    root
    aXc#,,Q_31ZmT9
    ru1.example.com

Разбор идёт скользящим окном с проверкой каждой позиции и рассинхронизацией на
одну строку при неудаче, а не простой нарезкой по пять. Причина конкретная: в
боевом файле в конце лежит посторонняя строка с паролем от панелей. Наивная
нарезка сдвинула бы на ней все последующие блоки, и пароли разъехались бы по
чужим серверам — молча.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from .config import harden_permissions
from .store import ServerProfile

_HEADER_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,15})\s*[-–—]\s*(?P<owner>\S+)$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_host(line: str) -> bool:
    try:
        ipaddress.ip_address(line)
        return True
    except ValueError:
        pass
    return _is_domain(line)


def _is_domain(line: str) -> bool:
    if "." not in line or len(line) > 253 or line.endswith("."):
        return False
    return all(_LABEL_RE.match(part) for part in line.split("."))


@dataclass
class ImportResult:
    profiles: list[ServerProfile]
    skipped: list[str]

    def preview(self) -> list[dict]:
        """Профили для показа человеку: пароль заменён на длину."""
        return [
            {**profile.public(), "password_len": len(profile.password)}
            for profile in self.profiles
        ]

    def save_skipped(self, path: Path) -> Path | None:
        """
        Сложить неразобранный хвост в отдельный файл.

        В боевом файле рядом с блоками серверов лежат доступы к панелям и
        ссылки — данные, которые в схему профиля не укладываются, но терять их
        нельзя. Пишем как есть, правами не ниже самого хранилища.
        """
        if not self.skipped:
            return None
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        body = "\n".join(
            [
                "# Строки из старого servers.env, не уложившиеся в формат блока.",
                "# Перенесены как есть при импорте — разобрать руками.",
                "",
                *self.skipped,
                "",
            ]
        )
        path.write_text(body, encoding="utf-8")
        harden_permissions(path)
        return path


def parse(text: str) -> ImportResult:
    lines = [line.strip().lstrip("﻿") for line in text.splitlines()]
    lines = [line for line in lines if line]

    profiles: list[ServerProfile] = []
    skipped: list[str] = []
    i = 0
    while i < len(lines):
        window = lines[i : i + 5]
        header = _HEADER_RE.match(window[0]) if window else None
        # Проверяем позиции 1, 2 и 5; четвёртая — пароль, а он может выглядеть
        # как угодно, включая как домен или как имя пользователя.
        if (
            header
            and len(window) == 5
            and _is_host(window[1])
            and _USER_RE.match(window[2])
            and _is_domain(window[4])
        ):
            name = header.group("name").lower()
            owner = header.group("owner").lower()
            profiles.append(
                ServerProfile(
                    name=name,
                    host=window[1],
                    user=window[2],
                    password=window[3],
                    domain=window[4],
                    label=window[0],
                    auth="password",
                    tags=[f"owner:{owner}", "imported"],
                )
            )
            i += 5
            continue

        skipped.append(lines[i])
        i += 1

    return ImportResult(profiles=profiles, skipped=skipped)


def parse_file(path: str | Path) -> ImportResult:
    source = Path(path).expanduser()
    if not source.exists():
        raise FileNotFoundError(f"файл {source} не найден")
    return parse(source.read_text(encoding="utf-8", errors="replace"))
