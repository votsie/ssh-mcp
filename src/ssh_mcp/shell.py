"""
Интерактивная PTY-сессия поверх ``invoke_shell()``.

Две проекции одного потока байт. Сырой кольцевой буфер отвечает на вопрос «что
нового с прошлого вызова», а экран pyte — на вопрос «что сейчас видно». Для
оболочки полезна первая, для nano или htop — вторая, и модуль сам определяет,
какая уместна, по флагу альтернативного экрана.

Читает отдельный поток, а не сам вызов тула. Причин три: если никто не читает,
окно SSH заполняется и удалённое приложение встаёт (htop замер бы между
вызовами); асинхронный вывод фонового задания не терялся бы; и логика «вывод
устоялся» сводится к чтению одной временной метки.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque

import paramiko
import pyte

from . import keymap, redact
from .config import log

RING_BYTES = 1 << 20      # столько сырого вывода держим для дельты
FEED_LIMIT = 128 << 10    # столько отдаём в pyte за один всплеск
POLL = 0.025

# Вход и выход в альтернативный экран. Куда надёжнее, чем пытаться выспросить
# состояние режима у pyte, и это лучший признак «работает полноэкранная TUI».
_ALT_ON = (b"\x1b[?1049h", b"\x1b[?47h", b"\x1b[?1047h")
_ALT_OFF = (b"\x1b[?1049l", b"\x1b[?47l", b"\x1b[?1047l")

_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_SS3 = re.compile(r"\x1bO.")
_OTHER_ESC = re.compile(r"\x1b[()][A-Za-z0-9]|\x1b[=><]")

MARKER = "__SSHMCP__"
MARKER_CONT = "__SSHMCP_CONT__"
# PS1 склеивается из двух половин намеренно: в эхе самой этой команды маркер
# тогда не появляется целиком, и ожидание приглашения не срабатывает на строке,
# которую мы же и набрали.
_H1, _H2 = MARKER[:5], MARKER[5:]
_C1, _C2 = MARKER_CONT[:5], MARKER_CONT[5:]
_SETUP = (
    "unset PROMPT_COMMAND; "
    f"PS1='{_H1}''{_H2} '; PS2='{_C1}''{_C2} '; "
    "stty -echoctl 2>/dev/null; clear"
)
# Запасной признак приглашения для оболочек, которые PS1 не слушают —
# у вендорских панелей это норма.
_GENERIC_PROMPT = re.compile(r"(?m)^.{0,120}[$#>%]\s?$")


def strip_ansi(text: str) -> str:
    """Убрать управляющие последовательности, оставив читаемый текст."""
    text = _OSC.sub("", text)      # OSC умеет менять заголовок и трогать буфер обмена
    text = _CSI.sub("", text)
    text = _SS3.sub("", text)
    text = _OTHER_ESC.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


class ShellSession:
    """Одна живая оболочка. Идентификатор присваивает реестр."""

    def __init__(self, server: str, channel: paramiko.Channel,
                 cols: int, rows: int, term: str):
        self.id = ""
        self.server = server
        self.term = term
        self.cols, self.rows = cols, rows

        self._chan = channel
        self._chan.settimeout(0.2)
        self._chan.set_combine_stderr(True)  # в PTY делить потоки бессмысленно

        self.screen = pyte.Screen(cols, rows)
        # strict=False: неизвестная xterm-последовательность должна быть
        # проигнорирована, а не поднять исключение внутри потока-читателя.
        self.stream = pyte.ByteStream(self.screen, strict=False)

        self._ring: deque[bytes] = deque()
        self._ring_bytes = 0
        self.total = 0
        self.offset = 0
        self.dropped = 0

        self.alt_screen = False
        self._echo = ""
        self.last_data = time.monotonic()
        self.last_used = time.monotonic()
        self.opened_at = time.monotonic()
        self._dead = False

        self.lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # ------------------------------------------------------------- чтение

    def _read_loop(self) -> None:
        while not self._dead:
            try:
                data = self._chan.recv(65536)
            except TimeoutError:
                continue
            except Exception:
                break
            if not data:
                break
            with self.lock:
                self._append(data)
                self._track_alt(data)
                self._feed(data)
                self.last_data = time.monotonic()
        self._dead = True

    def _append(self, data: bytes) -> None:
        self._ring.append(data)
        self._ring_bytes += len(data)
        self.total += len(data)
        while self._ring_bytes > RING_BYTES:
            head = self._ring.popleft()
            self._ring_bytes -= len(head)
            self.dropped += len(head)

    def _track_alt(self, data: bytes) -> None:
        for marker in _ALT_ON:
            if marker in data:
                self.alt_screen = True
        for marker in _ALT_OFF:
            if marker in data:
                self.alt_screen = False

    def _feed(self, data: bytes) -> None:
        # pyte — чистый Python. `cat` большого файла в PTY иначе занял бы ядро
        # на минуту; экран всё равно 40 строк, и рассинхрон состояния сам
        # чинится на ближайшей полной перерисовке.
        if len(data) > FEED_LIMIT:
            data = data[-FEED_LIMIT:]
        try:
            self.stream.feed(data)
        except Exception as exc:
            log.debug("pyte споткнулся: %s", exc)

    # ------------------------------------------------------------- запись

    def send(self, text: str = "", keys: list[str] | None = None,
             submit: bool = False) -> None:
        payload = text
        if keys:
            payload += keymap.resolve_all(keys, self.term)
        if submit:
            payload += keymap.ENTER
        if payload:
            self._chan.sendall(payload.encode("utf-8"))
        # Запоминаем набранное, чтобы ожидание не сработало на собственном эхе:
        # sshd возвращает введённую строку обратно, и `expect="nano"` совпал бы
        # с эхом команды `nano файл` ещё до того, как nano вообще запустился.
        self._echo = text.strip()
        self.last_used = time.monotonic()

    def _without_echo(self, text: str) -> str:
        """Отрезать всё до конца эха последней отправленной строки."""
        if not self._echo or len(self._echo) < 2:
            return text
        position = text.find(self._echo)
        if position < 0:
            return text
        return text[position + len(self._echo):]

    def resize(self, cols: int, rows: int) -> None:
        """
        Изменить размер окна.

        Порядок аргументов разный: у paramiko (width, height), у pyte
        (lines, columns). Перепутать их — получить тихо перекошенный экран.
        """
        self._chan.resize_pty(width=cols, height=rows)
        with self.lock:
            self.screen.resize(rows, cols)
            self.cols, self.rows = cols, rows

    # ---------------------------------------------------------- ожидание

    def wait(self, expect: str | None = None, idle_ms: int = 400,
             timeout_s: float = 20.0) -> tuple[str, str | None]:
        """
        Дождаться, пока вывод устоится.

        Три условия по убыванию точности: совпадение ``expect``, тишина
        ``idle_ms`` после хотя бы одного полученного байта, жёсткий предел
        ``timeout_s``. Возвращает, что именно сработало.
        """
        pattern = re.compile(expect) if expect else None
        start = time.monotonic()
        baseline = self.total
        deadline = start + timeout_s

        while time.monotonic() < deadline:
            with self.lock:
                total, last = self.total, self.last_data
            if pattern is not None:
                haystack = (
                    self._without_echo(self.new_output(peek=True))
                    + "\n"
                    + self._without_echo(self.render())
                )
                match = pattern.search(haystack)
                if match:
                    return "expect", match.group(0)
            # Тишина считается только после того, как что-то пришло: иначе
            # медленно стартующая команда «устоится» мгновенно и впустую.
            if total > baseline and (time.monotonic() - last) * 1000 >= idle_ms:
                return "idle", None
            if self._dead:
                return "closed", None
            time.sleep(POLL)
        return "timeout", None

    # ------------------------------------------------------------ проекции

    def new_output(self, peek: bool = False) -> str:
        """Текст, пришедший с прошлого вызова. Без ``peek`` сдвигает указатель."""
        with self.lock:
            start = max(self.offset, self.dropped)
            missed = max(0, self.dropped - self.offset)
            blob = b"".join(self._ring)
            begin = start - self.dropped
            chunk = blob[begin:]
            if not peek:
                self.offset = self.total
        text = strip_ansi(chunk.decode("utf-8", "replace"))
        if missed:
            text = f"[…потеряно {missed} байт, вывод был слишком большим…]\n" + text
        return redact.scrub(text)

    def render(self) -> str:
        """Текущий экран как его видел бы человек."""
        with self.lock:
            lines = [line.rstrip() for line in self.screen.display]
        while lines and not lines[-1]:
            lines.pop()
        return redact.scrub("\n".join(lines))

    def cursor(self) -> dict:
        with self.lock:
            return {"x": self.screen.cursor.x, "y": self.screen.cursor.y}

    def at_prompt(self) -> bool:
        lines = [line.rstrip() for line in self.render().splitlines() if line.strip()]
        if not lines:
            return False
        return lines[-1].endswith(MARKER) or bool(_GENERIC_PROMPT.match(lines[-1]))

    def at_continuation(self) -> bool:
        """
        Оболочка ждёт продолжения строки.

        Обычно это незакрытая кавычка: сессия молча съедает ввод, и без этого
        признака агент ждал бы таймаута за таймаутом, не понимая почему.
        """
        lines = [line for line in self.render().splitlines() if line.strip()]
        return bool(lines) and lines[-1].endswith(MARKER_CONT)

    def alive(self) -> bool:
        return not self._dead and not self._chan.closed

    def describe(self) -> dict:
        now = time.monotonic()
        last_line = ""
        for line in reversed(self.render().splitlines()):
            if line.strip():
                last_line = line.strip()[:100]
                break
        return {
            "session": self.id,
            "server": self.server,
            "alive": self.alive(),
            "alt_screen": self.alt_screen,
            "idle_s": round(now - self.last_used, 1),
            "age_s": round(now - self.opened_at, 1),
            "last_line": last_line,
        }

    def close(self) -> None:
        self._dead = True
        try:
            self._chan.close()
        except Exception:
            pass


def open_session(conn, cols: int = 120, rows: int = 40,
                 term: str = "xterm-256color", marker_prompt: bool = True) -> ShellSession:
    """Открыть оболочку и, если попросили, поставить опознаваемое приглашение."""
    channel = conn.client.invoke_shell(term=term, width=cols, height=rows)
    session = ShellSession(conn.profile.name, channel, cols, rows, term)

    if marker_prompt:
        # Ждём, пока оболочка проснётся, ставим маркер и стираем всю эту
        # техническую переписку из дельты, чтобы агент её не видел.
        session.wait(idle_ms=300, timeout_s=5)
        session.send(_SETUP, submit=True)
        session.wait(expect=re.escape(MARKER), idle_ms=300, timeout_s=5)
        session.new_output()
    return session
