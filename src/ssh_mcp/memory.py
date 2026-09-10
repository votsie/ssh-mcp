"""
Память о серверах и журнал действий.

Хранится в ``~/.ssh-mcp/memory/<имя>/``: ``facts.json`` пишет проба,
``notes.md`` — агент и человек. Формат заметок нарочно текстовый и плоский:
файл должен оставаться читаемым и правимым руками.

Отдельно ведётся ``history.jsonl`` — сухой журнал всех вызовов. Он ничего не
запрещает, но это единственный способ потом ответить на вопрос «что мы сделали
с сервером в прошлый вторник».
"""

from __future__ import annotations

import json
import threading
from datetime import date, datetime
from pathlib import Path

from . import redact
from .config import HISTORY_FILE, HISTORY_MAX_BYTES, MEMORY_DIR, harden_permissions, log

_lock = threading.Lock()

NOTES_LIMIT = 64 * 1024
DIGEST_NOTES = 3


def _dir(server: str) -> Path:
    path = MEMORY_DIR / server.strip().lower()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def read_facts(server: str) -> dict:
    path = _dir(server) / "facts.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("не читаются факты %s: %s", server, exc)
        return {}


def write_facts(server: str, facts: dict) -> None:
    if not facts:
        return
    path = _dir(server) / "facts.json"
    with _lock:
        path.write_text(
            json.dumps(facts, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    harden_permissions(path)


def read_notes(server: str) -> list[str]:
    path = _dir(server) / "notes.md"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line[2:].strip() for line in lines if line.startswith("- ")]


def add_note(server: str, note: str, tags: list[str] | None = None) -> dict:
    """
    Добавить заметку. Секреты вычищаются на записи, а не на чтении.

    Причина: ``notes.md`` защищён слабее хранилища доступов, и пароль,
    случайно скопированный агентом в заметку, осел бы там навсегда.
    """
    note = redact.scrub(note.strip().replace("\n", " "))
    if not note:
        return {"written": False, "reason": "пустая заметка"}

    prefix = "".join(f"[{tag}] " for tag in (tags or []))
    line = f"- {date.today().isoformat()} {prefix}{note}\n"
    path = _dir(server) / "notes.md"

    with _lock:
        if not path.exists():
            path.write_text(f"# {server}\n\n", encoding="utf-8")
            harden_permissions(path)
        size = path.stat().st_size
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    result = {"written": True, "note": note, "bytes": size + len(line)}
    if size > NOTES_LIMIT:
        result["warning"] = (
            f"заметки по {server} превысили {NOTES_LIMIT // 1024} КБ — стоит "
            f"проредить, иначе они перестанут помещаться в контекст"
        )
    return result


def digest(server: str) -> dict:
    """Короткая выжимка для ответа на подключение: факты и три свежие заметки."""
    notes = read_notes(server)
    return {
        "facts": read_facts(server),
        "notes_count": len(notes),
        "recent_notes": notes[-DIGEST_NOTES:],
    }


def forget(server: str) -> bool:
    path = MEMORY_DIR / server.strip().lower()
    if not path.exists():
        return False
    for child in path.iterdir():
        child.unlink()
    path.rmdir()
    return True


# ------------------------------------------------------------------ журнал


def record(tool: str, server: str | None = None, **details) -> None:
    """
    Записать вызов в журнал. Ошибка записи журнала не должна ломать работу.

    Значения секретных полей не сохраняются никогда — только их длина.
    """
    entry = {
        "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tool": tool,
        "server": server,
    }
    for key, value in details.items():
        if key in ("password", "passphrase", "secret", "value"):
            entry[f"{key}_len"] = len(value or "")
            continue
        entry[key] = redact.scrub_obj(value)

    try:
        with _lock:
            HISTORY_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > HISTORY_MAX_BYTES:
                HISTORY_FILE.replace(HISTORY_FILE.with_suffix(".jsonl.1"))
            with HISTORY_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        log.warning("журнал не пишется: %s", exc)


def history(server: str | None = None, limit: int = 50) -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    entries: list[dict] = []
    with HISTORY_FILE.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if server and entry.get("server") != server:
                continue
            entries.append(entry)
    return entries[-limit:]
