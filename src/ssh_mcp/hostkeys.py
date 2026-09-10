"""
Проверка ключей хостов.

Политика: читаем два файла, пишем только в свой.

``~/.ssh/known_hosts`` пользователя подхватываем на чтение — там уже закреплены
рабочие серверы, поэтому подключение к ним не требует ни одного подтверждения.
Но переписывать его нельзя: ``paramiko.HostKeys.save()`` нормализует файл
целиком и выбрасывает и комментарии, и маркеры ``@cert-authority`` / ``@revoked``,
на которые опирается настоящий ssh-клиент. Сломать пользователю OpenSSH — не та
цена, которую платят за удобство.

Первое подключение к незнакомому хосту закрепляет ключ автоматически (TOFU) —
это требование «без трения». Зато каждое следующее ведёт себя как RejectPolicy,
и именно там живёт вся защита.
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading

import paramiko

from .config import KNOWN_HOSTS, USER_KNOWN_HOSTS, log

_lock = threading.Lock()


def sha256_fingerprint(key: paramiko.PKey) -> str:
    """Отпечаток в формате ``ssh-keygen -l``: SHA256 + base64 без паддинга."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def lookup_name(hostname: str, port: int = 22) -> str:
    """
    Имя записи в known_hosts: ``host`` для 22-го порта, иначе ``[host]:port``.

    Идемпотентно и потому безопасно. Paramiko передаёт в политику имя уже
    отформатированным, и повторная обёртка давала ``[[host]:port]:port`` —
    запись после этого не находилась никогда, то есть проверка ключа хоста
    молча превращалась в её отсутствие.
    """
    if hostname.startswith("["):
        return hostname
    return hostname if port == 22 else f"[{hostname}]:{port}"


def _load(path) -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    if path.exists():
        try:
            keys.load(str(path))
        except (OSError, paramiko.SSHException) as exc:
            # Битая строка в чужом файле не повод не подключаться вообще.
            log.warning("не разобрал known_hosts %s: %s", path, exc)
    return keys


def load_all() -> paramiko.HostKeys:
    """Объединённый набор: сначала пользовательский файл, потом наш."""
    keys = _load(USER_KNOWN_HOSTS)
    for hostname, entries in _load(KNOWN_HOSTS).items():
        for keytype, key in entries.items():
            keys.add(hostname, keytype, key)
    return keys


def entry_source(hostname: str, port: int = 22) -> str | None:
    """Где закреплён ключ хоста — нужно, чтобы объяснить человеку расхождение."""
    lookup = lookup_name(hostname, port)
    if _load(USER_KNOWN_HOSTS).lookup(lookup):
        return str(USER_KNOWN_HOSTS)
    if _load(KNOWN_HOSTS).lookup(lookup):
        return str(KNOWN_HOSTS)
    return None


def _save_ours(keys: paramiko.HostKeys) -> None:
    KNOWN_HOSTS.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = KNOWN_HOSTS.with_suffix(".tmp")
    keys.save(str(tmp))
    os.replace(tmp, KNOWN_HOSTS)


def pin(hostname: str, key: paramiko.PKey, port: int = 22) -> str:
    """Закрепить ключ в нашем known_hosts. Возвращает отпечаток."""
    lookup = lookup_name(hostname, port)
    with _lock:
        ours = _load(KNOWN_HOSTS)
        ours.add(lookup, key.get_name(), key)
        _save_ours(ours)
    fingerprint = sha256_fingerprint(key)
    log.info("закреплён ключ %s для %s (%s)", key.get_name(), lookup, fingerprint)
    return fingerprint


def forget(hostname: str, port: int = 22) -> dict:
    """
    Убрать закрепление. Единственный законный выход из расхождения ключей.

    Чужой файл не трогаем: если запись лежит там, отдаём команду, которой
    человек уберёт её сам.
    """
    lookup = lookup_name(hostname, port)
    removed = False
    with _lock:
        ours = _load(KNOWN_HOSTS)
        if ours.lookup(lookup):
            del ours[lookup]
            _save_ours(ours)
            removed = True

    in_user_file = bool(_load(USER_KNOWN_HOSTS).lookup(lookup))
    result: dict = {"removed_from_ssh_mcp": removed, "also_in_user_known_hosts": in_user_file}
    if in_user_file:
        result["manual_step"] = (
            f'ssh-keygen -R "{lookup}"  # запись есть и в ~/.ssh/known_hosts, '
            f"этот файл ssh-mcp не правит"
        )
    return result


class TofuPolicy(paramiko.MissingHostKeyPolicy):
    """
    Trust-on-first-use: незнакомый ключ принимается и сразу закрепляется.

    Экземпляр одноразовый — после ``connect`` в нём лежит отчёт о том, что
    именно произошло, и он уходит в результат тула, чтобы человек мог сверить
    отпечаток глазами.
    """

    def __init__(self, port: int = 22) -> None:
        self.port = port
        self.action: str | None = None
        self.fingerprint: str | None = None
        self.key_type: str | None = None

    def missing_host_key(self, client, hostname, key) -> None:
        self.fingerprint = pin(hostname, key, self.port)
        self.key_type = key.get_name()
        self.action = "pinned-tofu"

    def report(self) -> dict:
        if self.action is None:
            return {"action": "known"}
        return {
            "action": self.action,
            "type": self.key_type,
            "fingerprint": self.fingerprint,
            "note": "Ключ хоста увиден впервые и закреплён. Сверьте отпечаток, "
                    "если сервер вам его называл.",
        }
