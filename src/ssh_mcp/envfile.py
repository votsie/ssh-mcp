"""
Мини-парсер и писатель ``.env``, рассчитанный на пароли.

Свой, а не ``python-dotenv``, по одной причине: гарантированный round-trip.
Боевой пароль вида ``aXc#,,Q_31ZmT9`` наивный парсер обрежет по ``#``, приняв
хвост за комментарий. Поэтому при записи значение всегда берётся в одинарные
кавычки по правилам POSIX-шелла (внутренний апостроф превращается в
последовательность «апостроф, обратный слэш, апостроф, апостроф»), а при
чтении поддерживаются три формы: одинарные кавычки, двойные и голое значение.
"""

from __future__ import annotations

SQ = "'"
ESCAPED_SQ = "'" + "\\" + "'" + "'"  # POSIX-склейка: '\''


def quote(value: str) -> str:
    """Завернуть значение в одинарные кавычки по правилам POSIX-шелла."""
    return SQ + value.replace(SQ, ESCAPED_SQ) + SQ


def _unquote_single(raw: str) -> str:
    # raw начинается с апострофа. Идём вручную, чтобы корректно собрать '\''.
    out: list[str] = []
    i = 1
    while i < len(raw):
        char = raw[i]
        if char != SQ:
            out.append(char)
            i += 1
            continue
        # Закрывающий апостроф. Склейка '\'' продолжает то же самое значение.
        if raw[i : i + len(ESCAPED_SQ)] == ESCAPED_SQ:
            out.append(SQ)
            i += len(ESCAPED_SQ)
            continue
        break
    return "".join(out)


_DOUBLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}


def _unquote_double(raw: str) -> str:
    out: list[str] = []
    i = 1
    while i < len(raw):
        char = raw[i]
        if char == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append(_DOUBLE_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        if char == '"':
            break
        out.append(char)
        i += 1
    return "".join(out)


def parse(text: str) -> tuple[dict[str, str], list[str]]:
    """
    Разобрать содержимое ``.env``.

    Возвращает пару: словарь ключ→значение и список нераспознанных строк
    (комментарии и пустые), которые писатель сохранит как есть.
    """
    values: dict[str, str] = {}
    other: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            other.append(line)
            continue

        key, _, raw = stripped.partition("=")
        key = key.strip()
        raw = raw.strip()
        if raw.startswith(SQ):
            values[key] = _unquote_single(raw)
        elif raw.startswith('"'):
            values[key] = _unquote_double(raw)
        else:
            # Голое значение забираем целиком: обрезать по '#' нельзя,
            # решётка — законный символ пароля.
            values[key] = raw
    return values, other


def render(pairs: list[tuple[str, str]], header: list[str] | None = None) -> str:
    """Собрать файл. Пара с пустым ключом даёт пустую строку-разделитель."""
    lines = list(header or [])
    for key, value in pairs:
        lines.append("" if not key else f"{key}={quote(value)}")
    return "\n".join(lines) + "\n"
