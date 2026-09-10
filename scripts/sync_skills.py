"""
Собрать skills/*/SKILL.md из руководств внутри пакета.

Один и тот же текст нужен и скиллам Claude Code, и агентам без скиллов. Держать
две копии руками — гарантированно получить расхождение, поэтому источник один,
а файлы скиллов генерируются. Тест сверяет, что они не разъехались.

Запуск: python scripts/sync_skills.py [--check]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ssh_mcp import guides  # noqa: E402

SKILLS = {
    "ssh-servers": {
        "topic": "servers",
        "description": (
            "Подключение к серверам по SSH, выполнение команд и сохранение новых "
            "серверов. Используй, когда пользователь даёт хост/IP с логином и "
            "паролем, называет имя сохранённого сервера, или просит что-то сделать "
            "на удалённой машине, VPS или сервере с панелью."
        ),
    },
    "ssh-interactive": {
        "topic": "interactive",
        "description": (
            "Управление интерактивными программами и полноэкранными интерфейсами "
            "по SSH — nano, vim, htop, меню dialog и whiptail, панели управления и "
            "любые команды, которые задают вопрос. Используй, когда команде нужно "
            "нажатие клавиши, ответ да/нет или она рисует полноэкранный интерфейс."
        ),
    },
    "ssh-ops": {
        "topic": "ops",
        "description": (
            "Обмен файлами с серверами по SFTP, копирование между серверами и "
            "SSH-туннели — проброс локального порта, удалённого порта и "
            "SOCKS5-прокси. Используй, когда нужно загрузить, скачать или перенести "
            "файл, либо достучаться с этой машины до удалённого порта, панели или "
            "базы данных."
        ),
    },
}

BANNER = "<!-- Собрано из src/ssh_mcp/guides/. Правьте источник, не этот файл. -->"


def render(name: str) -> str:
    spec = SKILLS[name]
    return (
        "---\n"
        f"name: {name}\n"
        f"description: {spec['description']}\n"
        "---\n\n"
        f"{BANNER}\n\n"
        f"{guides.read(spec['topic']).strip()}\n"
    )


def main() -> int:
    check = "--check" in sys.argv
    stale: list[str] = []
    for name in SKILLS:
        path = ROOT / "skills" / name / "SKILL.md"
        wanted = render(name)
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current == wanted:
            continue
        if check:
            stale.append(name)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(wanted, encoding="utf-8")
        print(f"обновлён skills/{name}/SKILL.md")

    if stale:
        print("разошлись с источником: " + ", ".join(stale))
        print("почините: python scripts/sync_skills.py")
        return 1
    print("скиллы совпадают с руководствами" if check else "готово")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
