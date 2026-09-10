"""Инструменты интерактивной консоли."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from . import keymap, memory, redact, registry, shell
from .server import _fail, mcp

_VIEWS = ("auto", "screen", "stream", "both")
TAIL_LINES = 3


def _shape(session: shell.ShellSession, settled: str, matched: str | None,
           view: str) -> dict:
    """
    Собрать ответ. По умолчанию отдаём одну проекцию из двух.

    Возвращать всегда обе — вдвое дороже по контексту, и в каждом из двух
    типичных режимов одна из них шум: в оболочке экран дублирует дельту, в
    htop дельта состоит из управляющих последовательностей.
    """
    stream_text = session.new_output()
    screen_text = session.render()

    if view == "auto":
        view = "screen" if session.alt_screen else "stream"

    result: dict = {
        "session": session.id,
        "server": session.server,
        "alive": session.alive(),
        "alt_screen": session.alt_screen,
        "at_prompt": session.at_prompt(),
        "settled": settled,
        "matched": matched,
        "cursor": session.cursor(),
    }
    if session.at_continuation():
        result["at_continuation"] = True
        result["hint"] = (
            "Оболочка ждёт продолжения строки — обычно это незакрытая кавычка. "
            "Отправьте keys=['ctrl-c'], иначе весь дальнейший ввод будет съеден."
        )

    def tail(text: str) -> str:
        lines = [line for line in text.splitlines() if line.strip()]
        return "\n".join(lines[-TAIL_LINES:])

    if view in ("stream", "both"):
        result["new_output"] = stream_text
    if view in ("screen", "both"):
        result["screen"] = screen_text
    if view == "stream":
        result["screen_tail"] = tail(screen_text)
    elif view == "screen":
        result["output_tail"] = tail(stream_text)

    if settled == "timeout":
        result["note"] = (
            "Вывод не устоялся за отведённое время. Обычно это значит «ещё "
            "работает» — вызовите ssh_shell_read ещё раз. Если экран не "
            "меняется несколько раз подряд, попробуйте keys=['ctrl-c']."
        )
    return result


@mcp.tool()
def ssh_shell_open(
    server: str,
    cols: int = 120,
    rows: int = 40,
    term: Annotated[str, Field(
        description="Тип терминала. xterm-256color по умолчанию; linux — если "
                    "приложение странно рисуется или не видит F-клавиши"
    )] = "xterm-256color",
    command: str | None = None,
    marker_prompt: bool = True,
) -> dict:
    """
    Открыть интерактивную оболочку на сервере.

    Нужна там, где команда что-то спрашивает или рисует полноэкранный
    интерфейс: nano, whiptail, htop, меню панелей. Для обычных команд берите
    ssh_run — он дешевле. Сессию по окончании закрывайте.
    """
    handle = registry.resolve(server)
    if len(registry.sessions()) >= 8:
        raise _fail(
            "уже открыто 8 сессий — закройте лишние через ssh_shell_close. "
            "Автоматически не вытесняю: в любой из них может быть "
            "несохранённый буфер редактора"
        )

    session = shell.open_session(
        handle.connection, cols=cols, rows=rows, term=term,
        marker_prompt=marker_prompt,
    )
    session_id = registry.add_session(session)
    memory.record("ssh_shell_open", server, session=session_id)

    settled, matched = "idle", None
    if command:
        session.send(command, submit=True)
        settled, matched = session.wait(idle_ms=500, timeout_s=20)
    return _shape(session, settled, matched, "auto")


@mcp.tool()
def ssh_shell_send(
    session: str,
    text: str | None = None,
    keys: Annotated[list[str] | None, Field(
        description="Имена клавиш по порядку, например ['ctrl-o','enter','ctrl-x']"
    )] = None,
    submit: Annotated[bool | None, Field(
        description="Дослать Enter. По умолчанию досылается для text и не "
                    "досылается, когда заданы keys — там Enter обычно уже в списке"
    )] = None,
    expect: Annotated[str | None, Field(
        description="Регулярка, до появления которой ждать. Точнее любого таймаута"
    )] = None,
    idle_ms: int = 400,
    timeout_s: float = 20.0,
    view: str = "auto",
) -> dict:
    """
    Отправить текст и/или нажатия клавиш в сессию и дождаться реакции.

    Работайте циклом: отправили — прочитали — посмотрели на экран — решили.
    Две отправки подряд вслепую почти всегда приводят к застрявшей сессии.
    """
    if view not in _VIEWS:
        raise _fail(f"view должен быть одним из {_VIEWS}")

    target = registry.get_session(session)
    if submit is None:
        submit = bool(text) and not keys

    try:
        target.send(text or "", keys, submit=submit)
    except keymap.UnknownKey as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        raise _fail(f"не удалось записать в сессию: {exc}") from exc

    settled, matched = target.wait(expect, idle_ms, timeout_s)
    memory.record("ssh_shell_send", target.server, session=session,
                  text=text, keys=keys, settled=settled)
    return _shape(target, settled, matched, view)


@mcp.tool()
def ssh_shell_send_secret(
    session: str,
    server_password: Annotated[str | None, Field(
        description="Имя сохранённого сервера — взять его пароль, не передавая его сюда"
    )] = None,
    value: str | None = None,
    idle_ms: int = 600,
    timeout_s: float = 20.0,
) -> dict:
    """
    Ввести пароль в приглашение sudo, passwd или установщика.

    Предпочитайте server_password: тогда пароль берётся из хранилища внутри
    процесса и вообще не проходит через переписку. Никогда не отправляйте
    пароль обычным ssh_shell_send — тот пишет текст в журнал.
    """
    from . import store

    target = registry.get_session(session)

    if server_password:
        profile = store.get(server_password)
        if profile is None or not profile.password:
            raise _fail(f"у сервера {server_password!r} нет сохранённого пароля")
        secret = profile.password
    elif value:
        secret = value
    else:
        raise _fail("нужен либо server_password, либо value")

    redact.remember(secret)
    target.send(secret, submit=True)
    settled, matched = target.wait(None, idle_ms, timeout_s)
    memory.record("ssh_shell_send_secret", target.server, session=session, secret=secret)
    return _shape(target, settled, matched, "auto")


@mcp.tool()
def ssh_shell_read(
    session: str,
    expect: str | None = None,
    idle_ms: int = 400,
    timeout_s: float = 20.0,
    view: str = "auto",
) -> dict:
    """Дочитать вывод сессии, ничего не отправляя — для длящихся команд."""
    if view not in _VIEWS:
        raise _fail(f"view должен быть одним из {_VIEWS}")
    target = registry.get_session(session)
    settled, matched = target.wait(expect, idle_ms, timeout_s)
    return _shape(target, settled, matched, view)


@mcp.tool()
def ssh_shell_resize(session: str, cols: int, rows: int) -> dict:
    """Изменить размер окна сессии. Полезно, если TUI обрезает содержимое."""
    target = registry.get_session(session)
    target.resize(cols, rows)
    return {"session": session, "cols": cols, "rows": rows, "screen": target.render()}


@mcp.tool()
def ssh_shell_close(session: str) -> dict:
    """Закрыть интерактивную сессию."""
    target = registry.get_session(session)
    server = target.server
    removed = registry.remove_session(session)
    memory.record("ssh_shell_close", server, session=session)
    return {"closed": removed, "session": session}


@mcp.tool()
def ssh_keys_list() -> dict:
    """Показать имена клавиш, которые понимает ssh_shell_send."""
    return {
        "keys": sorted(keymap.KEYS),
        "note": "alt-<символ> и meta-<символ> собираются на лету; "
                "суффикс -csi и -linux — запасные варианты F-клавиш",
    }
