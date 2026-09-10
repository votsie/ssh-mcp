"""
Именованные клавиши → байты, которые ждёт удалённое приложение.

Отдельный модуль, потому что это чистые данные, и их надо уметь проверить
тестом без всякой сети. Неизвестное имя — жёсткая ошибка со списком
допустимых: молчаливое «ничего не нажалось» стоило бы агенту нескольких
кругов вслепую.
"""

from __future__ import annotations

ENTER = "\r"  # именно CR: перевод в NL делает линейная дисциплина PTY

_BASE: dict[str, str] = {
    "enter": ENTER,
    "return": ENTER,
    "tab": "\t",
    "backtab": "\x1b[Z",
    "shift-tab": "\x1b[Z",
    "esc": "\x1b",
    "escape": "\x1b",
    "space": " ",
    "backspace": "\x7f",
    "delete": "\x1b[3~",
    "insert": "\x1b[2~",
    "up": "\x1b[A",
    "down": "\x1b[B",
    "right": "\x1b[C",
    "left": "\x1b[D",
    "home": "\x1b[H",
    "end": "\x1b[F",
    "home-ss3": "\x1bOH",
    "end-ss3": "\x1bOF",
    "pgup": "\x1b[5~",
    "pageup": "\x1b[5~",
    "pgdn": "\x1b[6~",
    "pagedown": "\x1b[6~",
    "y": "y",
    "n": "n",
}

# Функциональные клавиши: терминалы расходятся, а вендорские панели упрямы.
# Держим три набора и умеем переключаться по типу терминала.
_F_SS3 = {
    "f1": "\x1bOP", "f2": "\x1bOQ", "f3": "\x1bOR", "f4": "\x1bOS",
    "f5": "\x1b[15~", "f6": "\x1b[17~", "f7": "\x1b[18~", "f8": "\x1b[19~",
    "f9": "\x1b[20~", "f10": "\x1b[21~", "f11": "\x1b[23~", "f12": "\x1b[24~",
}
_F_CSI = {
    "f1": "\x1b[11~", "f2": "\x1b[12~", "f3": "\x1b[13~", "f4": "\x1b[14~",
}
_F_LINUX = {
    "f1": "\x1b[[A", "f2": "\x1b[[B", "f3": "\x1b[[C", "f4": "\x1b[[D",
    "f5": "\x1b[[E",
}


def _build() -> dict[str, str]:
    table = dict(_BASE)
    table.update(_F_SS3)
    for name, seq in _F_CSI.items():
        table[f"{name}-csi"] = seq
    for name, seq in _F_LINUX.items():
        table[f"{name}-linux"] = seq
    # Ctrl-<буква> — управляющий символ; ctrl-o и ctrl-x это «сохранить» и
    # «выйти» в nano, ими закрывается самый частый интерактивный сценарий.
    for code in range(ord("a"), ord("z") + 1):
        table[f"ctrl-{chr(code)}"] = chr(code - 96)
    table["ctrl-space"] = "\x00"
    table["ctrl-]"] = "\x1d"
    table["ctrl-\\"] = "\x1c"
    return table


KEYS = _build()

TERM_F_OVERRIDES = {"linux": _F_LINUX}


class UnknownKey(KeyError):
    """Имя клавиши не распознано."""


def resolve(name: str, term: str = "xterm-256color") -> str:
    """Перевести имя клавиши в байты для указанного типа терминала."""
    key = name.strip().lower()

    override = TERM_F_OVERRIDES.get(term)
    if override and key in override:
        return override[key]

    if key.startswith(("alt-", "meta-")) and len(key.split("-", 1)[1]) == 1:
        return "\x1b" + key.split("-", 1)[1]

    try:
        return KEYS[key]
    except KeyError:
        raise UnknownKey(
            f"клавиша {name!r} не распознана. Допустимые имена: "
            + ", ".join(sorted(KEYS))
        ) from None


def resolve_all(names: list[str], term: str = "xterm-256color") -> str:
    return "".join(resolve(name, term) for name in names)
