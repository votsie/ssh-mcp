import pytest

from ssh_mcp import keymap, shell
from ssh_mcp.keymap import UnknownKey


# ------------------------------------------------------------- карта клавиш


def test_enter_is_carriage_return():
    """CR, а не LF: перевод делает линейная дисциплина PTY на той стороне."""
    assert keymap.resolve("enter") == "\r"


@pytest.mark.parametrize("name,expected", [
    ("ctrl-c", "\x03"),
    ("ctrl-d", "\x04"),
    ("ctrl-o", "\x0f"),   # nano: записать файл
    ("ctrl-x", "\x18"),   # nano: выйти
    ("up", "\x1b[A"),
    ("tab", "\t"),
    ("esc", "\x1b"),
    ("backspace", "\x7f"),
    ("f6", "\x1b[17~"),
    ("f1", "\x1bOP"),
    ("alt-y", "\x1by"),
])
def test_known_keys(name, expected):
    assert keymap.resolve(name) == expected


def test_case_and_space_are_forgiving():
    assert keymap.resolve("  Ctrl-C ") == "\x03"


def test_linux_term_remaps_function_keys():
    """У terminfo linux F-клавиши другие, и панели на это натыкаются."""
    assert keymap.resolve("f1", term="xterm-256color") == "\x1bOP"
    assert keymap.resolve("f1", term="linux") == "\x1b[[A"


def test_csi_alias_available():
    assert keymap.resolve("f1-csi") == "\x1b[11~"


def test_unknown_key_is_a_hard_error_listing_valid_names():
    with pytest.raises(UnknownKey) as excinfo:
        keymap.resolve("supr")
    message = str(excinfo.value)
    assert "не распознана" in message
    assert "ctrl-c" in message, "ошибка обязана перечислять допустимые имена"


def test_resolve_all_concatenates():
    assert keymap.resolve_all(["ctrl-o", "enter", "ctrl-x"]) == "\x0f\r\x18"


# ------------------------------------------------------- очистка от ESC


def test_strip_ansi_removes_colours_and_cursor_moves():
    raw = "\x1b[1;32mзелёный\x1b[0m\x1b[2J\x1b[H обычный"
    assert shell.strip_ansi(raw) == "зелёный обычный"


def test_strip_ansi_removes_osc():
    """OSC меняет заголовок окна, а кое-где лезет в буфер обмена."""
    raw = "\x1b]0;заголовок\x07текст"
    assert shell.strip_ansi(raw) == "текст"


def test_strip_ansi_normalises_line_endings():
    assert shell.strip_ansi("a\r\nb\rc") == "a\nb\nc"


# --------------------------------------------------- живая сессия на sshd


@pytest.fixture()
def session(conn):
    created = shell.open_session(conn, cols=80, rows=24, marker_prompt=False)
    created.id = "s-test"
    yield created
    created.close()


def test_shell_echoes_and_reports_output(session):
    session.wait(idle_ms=200, timeout_s=3)
    session.new_output()
    session.send("echo привет", submit=True)
    settled, _ = session.wait(expect="привет", idle_ms=300, timeout_s=5)
    assert settled == "expect"
    assert "привет" in session.new_output()


def test_expect_reports_what_matched(session):
    session.wait(idle_ms=200, timeout_s=3)
    session.new_output()
    session.send("echo READY-42", submit=True)
    settled, matched = session.wait(expect=r"READY-\d+", idle_ms=300, timeout_s=5)
    assert settled == "expect" and matched == "READY-42"


def test_idle_settles_when_nothing_matches(session):
    session.wait(idle_ms=200, timeout_s=3)
    session.send("echo tick", submit=True)
    settled, _ = session.wait(idle_ms=200, timeout_s=5)
    assert settled == "idle"


def test_alt_screen_is_detected(session):
    """Признак «работает полноэкранная TUI» — вход в альтернативный экран."""
    session.wait(idle_ms=200, timeout_s=3)
    assert session.alt_screen is False
    session.send("tui", submit=True)
    session.wait(expect="ALT SCREEN", idle_ms=300, timeout_s=5)
    assert session.alt_screen is True
    session.send("untui", submit=True)
    session.wait(idle_ms=300, timeout_s=5)
    assert session.alt_screen is False


def test_screen_is_rendered_not_escape_soup(session):
    session.wait(idle_ms=200, timeout_s=3)
    session.send("tui", submit=True)
    session.wait(expect="ALT SCREEN", idle_ms=300, timeout_s=5)
    screen = session.render()
    assert "ALT SCREEN" in screen
    assert "\x1b" not in screen, "в отрендеренном экране не должно быть ESC"


def test_keys_are_delivered(session):
    session.wait(idle_ms=200, timeout_s=3)
    session.new_output()
    session.send("echo x", keys=["enter"])
    session.wait(idle_ms=300, timeout_s=5)
    assert "x" in session.new_output()


def test_new_output_is_a_delta(session):
    session.wait(idle_ms=200, timeout_s=3)
    session.new_output()
    session.send("echo первый", submit=True)
    session.wait(expect="первый", idle_ms=300, timeout_s=5)
    first = session.new_output()
    assert "первый" in first

    session.send("echo второй", submit=True)
    session.wait(expect="второй", idle_ms=300, timeout_s=5)
    second = session.new_output()
    assert "второй" in second
    assert "первый" not in second, "дельта не должна повторять уже прочитанное"


def test_resize_uses_correct_argument_order(session):
    """paramiko принимает (width, height), pyte — (lines, columns)."""
    session.resize(100, 30)
    assert session.cols == 100 and session.rows == 30
    assert session.screen.columns == 100
    assert session.screen.lines == 30


def test_describe_and_close(session):
    info = session.describe()
    assert info["server"] == "loop" and info["alive"] is True
    session.close()
    assert session.alive() is False


def test_secret_is_scrubbed_from_output(session, monkeypatch):
    """Эхо в PTY на совести sshd, поэтому пароль чистим по факту."""
    from ssh_mcp import redact

    redact.remember("sup3rs3cret")
    session.wait(idle_ms=200, timeout_s=3)
    session.new_output()
    session.send("echo sup3rs3cret", submit=True)
    session.wait(idle_ms=400, timeout_s=5)
    text = session.new_output()
    assert "sup3rs3cret" not in text
    assert redact.MASK in text


def test_expect_does_not_match_the_echo_of_our_own_command(session):
    """
    Регрессия: sshd возвращает набранную строку эхом, и expect='nano' совпадал
    с эхом команды `nano файл` ещё до того, как nano успевал запуститься.
    """
    session.wait(idle_ms=200, timeout_s=3)
    session.new_output()
    # Слово встречается и в самой команде, и в ответе сервера. Совпасть должно
    # именно по ответу, а не по эху.
    session.send("маркер-эха", submit=True)
    settled, _ = session.wait(expect="маркер-эха", idle_ms=200, timeout_s=6)
    assert settled == "expect"
    tail = session._without_echo(session.new_output())
    assert "ok" in tail, f"совпадение пришлось на эхо, а не на ответ: {tail!r}"


def test_without_echo_trims_only_the_first_occurrence():
    from ssh_mcp.shell import ShellSession

    trimmer = ShellSession.__new__(ShellSession)
    trimmer._echo = "nano /tmp/x"
    assert trimmer._without_echo("nano /tmp/x\nGNU nano 7.2") == "\nGNU nano 7.2"
    assert trimmer._without_echo("ничего похожего") == "ничего похожего"


def test_without_echo_ignores_too_short_echo():
    from ssh_mcp.shell import ShellSession

    trimmer = ShellSession.__new__(ShellSession)
    trimmer._echo = "y"
    assert trimmer._without_echo("yes") == "yes", "односимвольный ввод резать нельзя"
