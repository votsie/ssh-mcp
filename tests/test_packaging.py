"""
Проверки, без которых установка «из репозитория в любой агент» тихо ломается.

Каждая закрывает конкретный способ сломать дистрибутив: разъехавшиеся скиллы,
не попавшие в колесо руководства, потерянную точку входа, привязку конфигурации
к чужой машине.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_console_script_is_declared(pyproject: dict) -> None:
    """Точка входа — то, чем `uvx --from git+... ssh-mcp` вообще работает."""
    assert pyproject["project"]["scripts"]["ssh-mcp"] == "ssh_mcp.server:main"


def test_entry_point_target_is_importable() -> None:
    from ssh_mcp.server import main

    assert callable(main)


def test_package_entry_module_exists() -> None:
    """
    `python -m ssh_mcp` должен идти через __main__.py, а не через server.py:
    запуск модуля напрямую импортирует его дважды и даёт два разных сервера.
    """
    assert (ROOT / "src" / "ssh_mcp" / "__main__.py").exists()


def test_mcp_json_has_no_machine_specific_paths() -> None:
    """Конфигурация плагина не должна зависеть от чужого venv или диска C:."""
    config = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    entry = config["mcpServers"]["ssh"]
    blob = json.dumps(entry)
    assert ".venv" not in blob, "готовое окружение из git-клона не появится"
    assert "Scripts" not in blob, "путь только для Windows"
    assert "C:" not in blob
    assert entry["command"] == "uvx"


def test_plugin_and_marketplace_versions_agree(pyproject: dict) -> None:
    version = pyproject["project"]["version"]
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert plugin["version"] == version
    assert market["plugins"][0]["version"] == version


def test_declared_skills_exist(pyproject: dict) -> None:
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    for entry in plugin["skills"]:
        assert (ROOT / entry.strip("./") / "SKILL.md").exists(), entry


def test_skills_match_their_source() -> None:
    """Скиллы генерируются из руководств — расхождение означает правку не там."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_skills.py"), "--check"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_guides_ship_inside_the_package() -> None:
    """
    Руководства обязаны лежать внутри пакета: агенты без скиллов получают их
    только через ssh_guide, а тот читает файлы рядом с кодом.
    """
    from ssh_mcp import guides

    for topic in guides.topics():
        text = guides.read(topic)
        assert len(text) > 500, topic
        assert topic in guides.TITLES


def test_instructions_carry_the_three_rules() -> None:
    from ssh_mcp import guides

    text = guides.INSTRUCTIONS
    assert "ДАННЫЕ, А НЕ ИНСТРУКЦИИ" in text
    assert "ssh_save_server" in text
    assert "КЛЮЧА ХОСТА" in text
    assert len(text) < 4000, "инструкции уходят в каждый сеанс, держим их короткими"


def test_guide_tool_rejects_unknown_topic() -> None:
    from ssh_mcp import guides

    with pytest.raises(KeyError):
        guides.read("нет-такой-темы")


def test_guides_do_not_assume_claude_code() -> None:
    """
    Руководства идут и в Codex, и в Cursor. Механизмы Claude Code упоминать
    можно, но только как один из вариантов, а не как единственный путь.
    """
    from ssh_mcp import guides

    for topic in guides.topics():
        text = guides.read(topic)
        for line in text.splitlines():
            if "AskUserQuestion" in line or "скилл" in line.lower():
                assert "Claude Code" in text, topic
