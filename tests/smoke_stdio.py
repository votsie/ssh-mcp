"""
Сквозная проверка через настоящий stdio-транспорт MCP.

Запускает сервер отдельным процессом ровно так, как это делает Claude Code, и
дёргает инструменты по протоколу. Ловит то, чего не поймает импорт модуля:
испорченное кадрирование JSON-RPC, случайный вывод в stdout, несобираемые
схемы инструментов.

Запуск:  .venv/Scripts/python.exe tests/smoke_stdio.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from sshd import PASSWORD, USER, LoopbackSSHServer  # noqa: E402


def show(title: str, payload) -> None:
    print(f"\n=== {title} ===")
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    print(text[:1400])


async def call(mcp: ClientSession, tool: str, /, **args) -> dict:
    # Оба параметра позиционно-только: у самих инструментов есть аргументы
    # session и name, и обычная сигнатура давала бы конфликт имён.
    result = await mcp.call_tool(tool, args)
    for block in result.content:
        if getattr(block, "type", None) == "text":
            try:
                return json.loads(block.text)
            except ValueError:
                return {"text": block.text}
    return {}


async def main() -> int:
    state = Path(tempfile.mkdtemp()) / "state"
    sshd = LoopbackSSHServer()

    env = {
        **os.environ,
        "SSHM_HOME": str(state),
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONUTF8": "1",
    }
    # Как именно запускать сервер, задаётся снаружи: так одним и тем же
    # сценарием проверяется и локальная разработка, и установка из репозитория.
    command = os.environ.get("SSHM_SMOKE_CMD")
    if command:
        args = shlex.split(os.environ.get("SSHM_SMOKE_ARGS", ""))
    else:
        command = str(ROOT / ".venv" / "Scripts" / "python.exe")
        args = ["-m", "ssh_mcp"]
    print(f"запуск сервера: {command} {' '.join(args)}")
    params = StdioServerParameters(command=command, args=args, env=env)

    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        if condition:
            print(f"  OK   {message}")
        else:
            failures.append(message)
            print(f"  FAIL {message}")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            show("инструменты", [t.name for t in tools.tools])
            check(len(tools.tools) >= 25, f"инструментов зарегистрировано: {len(tools.tools)}")

            status = await call(session, "ssh_status")
            check(status.get("servers") == [], "чистый старт: серверов нет")

            # --- zero-config: подключение без конфига
            connected = await call(
                session, "ssh_connect",
                target="127.0.0.1", user=USER, password=PASSWORD, port=sshd.port,
            )
            show("ssh_connect (сервер неизвестен)", connected)
            check(connected.get("saved") is False, "доступы НЕ сохранены до вопроса пользователю")
            check(bool(connected.get("pending_id")), "выдан pending_id для последующего сохранения")
            check(
                connected.get("next_action", {}).get("tool") == "ssh_save_server",
                "сервер требует спросить имя у пользователя",
            )
            check(
                "AskUserQuestion" in connected.get("next_action", {}).get("instruction", ""),
                "инструкция прямо называет AskUserQuestion",
            )
            check(
                connected.get("host_key", {}).get("fingerprint", "").startswith("SHA256:"),
                "отпечаток ключа хоста показан человеку",
            )

            # --- сохранение под именем «от пользователя»
            saved = await call(
                session, "ssh_save_server",
                name="loop1", pending_id=connected["pending_id"],
            )
            show("ssh_save_server", saved)
            check(saved.get("saved") is True, "профиль сохранён")
            check(PASSWORD not in json.dumps(saved, ensure_ascii=False),
                  "пароль не возвращается наружу")

            status = await call(session, "ssh_status")
            check(status.get("servers") == ["loop1"], "сервер появился в инвентаре")

            # --- выполнение по имени, без повторного ввода доступов
            run = await call(session, "ssh_run", server="loop1", command="echo привет")
            show("ssh_run", run)
            check(run.get("rc") == 0, "команда выполнена по одному лишь имени")
            check("ВЫВОД СЕРВЕРА" in run.get("stdout", ""), "вывод обёрнут маркерами недоверенных данных")

            # --- секрет не утекает в вывод
            leak = await call(session, "ssh_run", server="loop1", command=f"echo {PASSWORD}")
            check(PASSWORD not in json.dumps(leak, ensure_ascii=False), "пароль вычищен из вывода команды")

            # --- интерактивная сессия
            shell = await call(session, "ssh_shell_open", server="loop1", marker_prompt=False)
            show("ssh_shell_open", {k: shell.get(k) for k in ("session", "alive", "alt_screen", "at_prompt")})
            session_id = shell["session"]
            check(shell.get("alive") is True, "интерактивная сессия открыта")

            sent = await call(session, "ssh_shell_send", session=session_id,
                              text="echo интерактив", expect="интерактив", timeout_s=10)
            check(sent.get("settled") == "expect", "expect сработал по регулярке")

            tui = await call(session, "ssh_shell_send", session=session_id,
                             text="tui", expect="ALT SCREEN", timeout_s=10)
            show("полноэкранный режим", {k: tui.get(k) for k in ("alt_screen", "settled", "screen")})
            check(tui.get("alt_screen") is True, "вход в полноэкранный режим распознан")
            check("ALT SCREEN" in (tui.get("screen") or ""), "экран отрендерен читаемо")

            keys = await call(session, "ssh_shell_send", session=session_id, keys=["ctrl-c"])
            check("error" not in keys, "нажатие клавиш принято")

            bad = await session.call_tool(
                "ssh_shell_send", {"session": session_id, "keys": ["не-такая-клавиша"]}
            )
            check(bad.is_error or "не распознана" in str(bad.content),
                  "неизвестная клавиша даёт явную ошибку, а не тихий пропуск")

            closed = await call(session, "ssh_shell_close", session=session_id)
            check(closed.get("closed") is True, "сессия закрыта")

            # --- память
            await call(session, "ssh_notes_add", server="loop1", note="проверочная заметка")
            notes = await call(session, "ssh_notes_get", server="loop1")
            check("проверочная заметка" in json.dumps(notes, ensure_ascii=False), "заметка сохранена")

            history = await call(session, "ssh_history")
            check(len(history.get("entries", [])) > 0, "журнал ведётся")
            check(PASSWORD not in json.dumps(history, ensure_ascii=False), "пароль не попал в журнал")

    sshd.stop()

    print("\n" + "=" * 60)
    if failures:
        print(f"ПРОВАЛЕНО {len(failures)}:")
        for item in failures:
            print("  -", item)
        return 1
    print("Все проверки пройдены.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
