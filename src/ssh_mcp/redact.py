"""
Вычищение секретов из всего, что уходит агенту или в лог.

Приём простой и потому надёжный: процесс помнит множество известных секретных
строк (пароли из хранилища, парольные фразы, всё отправленное с ``secret=true``)
и заменяет их на маркер в любом возвращаемом значении.

Почему не «просто не печатать пароль». В PTY-режиме эхо целиком на стороне
sshd: ``Channel.get_pty()`` в paramiko отправляет пустое поле terminal modes и
API для выключения ECHO не даёт. Приглашения ``sudo``/``passwd`` гасят эхо
сами, но текст, введённый в обычной строке, вернётся в выводе. Поэтому чистим
по факту, а не рассчитываем на отсутствие эха.
"""

from __future__ import annotations

import re
import threading
from typing import Any

MASK = "«скрыто»"
_MIN_LEN = 6  # короче — слишком много ложных срабатываний по всему выводу

# Приватный ключ, случайно выведенный в консоль, — такой же секрет, но в
# множестве известных строк его нет: чистим по форме.
_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

_lock = threading.Lock()
_secrets: set[str] = set()


def remember(*values: str | None) -> None:
    """Запомнить секреты. Пустые и слишком короткие значения игнорируются."""
    with _lock:
        for value in values:
            if value and len(value) >= _MIN_LEN:
                _secrets.add(value)


def forget_all() -> None:
    """Только для тестов."""
    with _lock:
        _secrets.clear()


def scrub(text: str) -> str:
    """Заменить все известные секреты в строке на маркер."""
    if not text:
        return text
    with _lock:
        # Длинные сначала: иначе короткий секрет, входящий в длинный,
        # разрежет его и остаток длинного утечёт.
        current = sorted(_secrets, key=len, reverse=True)
    for secret in current:
        if secret in text:
            text = text.replace(secret, MASK)
    return _PEM.sub("-----PRIVATE KEY " + MASK + "-----", text)


def scrub_obj(obj: Any) -> Any:
    """Рекурсивно применить scrub к строкам внутри структуры."""
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, dict):
        return {key: scrub_obj(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [scrub_obj(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(scrub_obj(item) for item in obj)
    return obj
