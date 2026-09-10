"""
Локальный SSH-сервер на paramiko для тестов.

Нужен, чтобы проверять коннект, аутентификацию, drain-цикл, таймауты и
проброс портов, не трогая боевые серверы и не требуя Docker.
"""

from __future__ import annotations

import socket
import threading
import time

import paramiko

USER = "tester"
PASSWORD = "loopback-pass"


class _Handler(paramiko.ServerInterface):
    def __init__(self, owner: "LoopbackSSHServer"):
        self.owner = owner
        # Состояние ДОЛЖНО быть на канал, а не на соединение: после exec-пробы
        # следующий запрос shell иначе принимается за тот же exec.
        self.requests: dict[int, tuple[str, str | None]] = {}
        self.destinations: dict[int, tuple[str, int]] = {}

    # --- аутентификация

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        if username == USER and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username == USER and self.owner.authorized_key is not None:
            if key.asbytes() == self.owner.authorized_key.asbytes():
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    # --- каналы

    def check_channel_request(self, kind, chanid):
        if kind in ("session", "direct-tcpip"):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        # Запоминаем цель по номеру канала: transport.accept() отдаёт канал,
        # но не адрес, а без адреса пробрасывать некуда.
        self.owner.forwarded.append(destination)
        self.destinations[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height, *args):
        self.owner.pty_requests.append((term, width, height))
        return True

    def check_channel_shell_request(self, channel):
        self.requests[channel.get_id()] = ("shell", None)
        return True

    def check_channel_exec_request(self, channel, command):
        self.requests[channel.get_id()] = ("exec", command.decode("utf-8", "replace"))
        return True

    def check_channel_window_change_request(self, channel, width, height, *args):
        self.owner.resizes.append((width, height))
        return True


class LoopbackSSHServer:
    """
    Однопоточный SSH-сервер на 127.0.0.1 со случайным портом.

    ``exec`` обслуживается словарём ответов; несколько команд имеют особое
    поведение, нужное для проверки крайних случаев drain-цикла.
    """

    def __init__(self) -> None:
        self.host_key = paramiko.RSAKey.generate(2048)
        self.authorized_key: paramiko.PKey | None = None
        self.responses: dict[str, tuple[int, str, str]] = {}
        self.forwarded: list[tuple[str, int]] = []
        self.pty_requests: list[tuple[str, int, int]] = []
        self.resizes: list[tuple[int, int]] = []

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._accepter = threading.Thread(target=self._accept_loop, daemon=True)
        self._accepter.start()

    # --- жизненный цикл

    def _accept_loop(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._serve, args=(client,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _serve(self, sock: socket.socket) -> None:
        transport = paramiko.Transport(sock)
        transport.add_server_key(self.host_key)
        handler = _Handler(self)
        try:
            transport.start_server(server=handler)
        except paramiko.SSHException:
            return

        while not self._stop.is_set():
            channel = transport.accept(0.5)
            if channel is None:
                if not transport.is_active():
                    return
                continue
            destination = handler.destinations.pop(channel.get_id(), None)
            target = self._forward if destination else self._serve_channel
            args = (channel, destination) if destination else (channel, handler)
            threading.Thread(target=target, args=args, daemon=True).start()

    def _forward(self, channel: paramiko.Channel, destination) -> None:
        """Настоящий direct-tcpip: соединяемся с целью и качаем в обе стороны."""
        try:
            sock = socket.create_connection(destination, timeout=5)
        except OSError:
            channel.close()
            return

        def pump(src, dst, is_channel_src):
            try:
                while True:
                    data = src.recv(32768)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for item in (channel, sock):
                    try:
                        item.close()
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(channel, sock, True), daemon=True).start()
        threading.Thread(target=pump, args=(sock, channel, False), daemon=True).start()

    def _serve_channel(self, channel: paramiko.Channel, handler: _Handler) -> None:
        deadline = time.monotonic() + 5
        request = None
        while time.monotonic() < deadline:
            request = handler.requests.pop(channel.get_id(), None)
            if request is not None:
                break
            time.sleep(0.02)
        if request is None:
            channel.close()
            return

        kind, command = request
        if kind == "shell":
            self._run_shell(channel)
            return

        command = command or ""
        rc, out, err = self._respond(command, channel)
        if out:
            channel.sendall(out.encode("utf-8"))
        if err:
            channel.sendall_stderr(err.encode("utf-8"))
        channel.send_exit_status(rc)
        channel.close()

    def _respond(self, command: str, channel: paramiko.Channel):
        if command in self.responses:
            return self.responses[command]
        if command.startswith("sleep-forever"):
            while not self._stop.is_set():
                time.sleep(0.05)
            return 0, "", ""
        if command.startswith("bigout"):
            # Много данных в оба потока сразу: ровно тот случай, на котором
            # заклинивает наивное чтение одного потока.
            count = int(command.split()[1])
            for i in range(count):
                channel.sendall(f"stdout line {i}\n".encode())
                channel.sendall_stderr(f"stderr line {i}\n".encode())
            return 0, "", ""
        if command.startswith("exit "):
            return int(command.split()[1]), "", ""
        if command.startswith("echo "):
            return 0, command[5:] + "\n", ""
        return 127, "", f"{command}: command not found\n"

    def _run_shell(self, channel: paramiko.Channel) -> None:
        """Простейшая оболочка-эхо, достаточная для проверки PTY-цикла."""
        channel.sendall(b"loopback shell\r\n$ ")
        buffer = b""
        while not self._stop.is_set() and not channel.closed:
            try:
                data = channel.recv(1024)
            except Exception:
                break
            if not data:
                break
            channel.sendall(data)  # эхо, как настоящая линейная дисциплина
            buffer += data
            while b"\r" in buffer:
                line, _, buffer = buffer.partition(b"\r")
                text = line.decode("utf-8", "replace").strip()
                channel.sendall(b"\r\n")
                if text in ("exit", "logout"):
                    channel.send_exit_status(0)
                    channel.close()
                    return
                if text.startswith("echo "):
                    channel.sendall(text[5:].encode() + b"\r\n")
                elif text == "tui":
                    # вход в альтернативный экран и обратно
                    channel.sendall(b"\x1b[?1049h\x1b[2J\x1b[HALT SCREEN\r\n")
                elif text == "untui":
                    channel.sendall(b"\x1b[?1049l")
                elif text:
                    channel.sendall(text.encode() + b": ok\r\n")
                channel.sendall(b"$ ")

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "LoopbackSSHServer":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
