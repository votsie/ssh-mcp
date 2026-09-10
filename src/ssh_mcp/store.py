"""
Хранилище профилей серверов: ``~/.ssh-mcp/servers.env``.

Формат — плоский ``.env`` с ключами ``SSHM_<СЛАГ>_<ПОЛЕ>``, читаемый и правимый
руками. Это осознанное требование: пароли лежат открытым текстом, зато конфиг
можно поправить блокнотом.

Списка серверов отдельным ключом нет намеренно — набор слагов выводится из
самих ключей. Отдельный реестр рано или поздно разъезжается с содержимым, и
тогда сервер есть, а в списке его нет.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from . import envfile, redact
from .config import SERVERS_ENV, harden_permissions, log

_HEADER = [
    "# ssh-mcp — хранилище доступов. Открытый текст, режим 0600.",
    "# Не коммитить. Правится руками: значения в одинарных кавычках.",
    "# schema: 1",
    "",
]

_PREFIX = "SSHM_"

# Поля профиля в порядке записи в файл.
_FIELDS = (
    "name", "label", "host", "port", "user", "password",
    "key_file", "passphrase", "auth", "domain", "jump", "tags",
    "added", "last_ok",
)

# Имя поля берётся из известного списка, а не «всё после последнего
# подчёркивания». Жадный разбор растаскивал SSHM_NL1_KEY_FILE на слаг NL1_KEY
# и поле FILE, порождая фантомные профили из ничего. Слаг нежадный, хвост
# закреплён за реальным полем.
_KEY_RE = re.compile(
    r"^SSHM_(?P<slug>[A-Z][A-Z0-9_]*?)_(?P<fld>"
    + "|".join(sorted((field.upper() for field in _FIELDS), key=len, reverse=True))
    + r")$"
)

_lock = threading.RLock()


class StoreError(RuntimeError):
    """Ошибка чтения или записи хранилища."""


def slugify(name: str) -> str:
    """Имя сервера → слаг для ключей .env. ``nl-2`` и ``nl_2`` дают один слаг."""
    slug = re.sub(r"[^A-Za-z0-9]", "_", name).upper()
    if not slug or not slug[0].isalpha():
        slug = "S" + slug
    return slug


@dataclass
class ServerProfile:
    """Один сохранённый сервер."""

    name: str
    host: str
    user: str = "root"
    port: int = 22
    password: str = ""
    key_file: str = ""
    passphrase: str = ""
    auth: str = "auto"  # auto | password | key | agent
    label: str = ""
    domain: str = ""
    jump: str = ""
    tags: list[str] = field(default_factory=list)
    added: str = ""
    last_ok: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"

    def public(self) -> dict:
        """Представление для агента: наличие секретов, но не сами секреты."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "auth": self.auth,
            "has_password": bool(self.password),
            "has_key": bool(self.key_file),
            "label": self.label,
            "domain": self.domain,
            "jump": self.jump,
            "tags": list(self.tags),
            "added": self.added,
            "last_ok": self.last_ok,
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ------------------------------------------------------------------- чтение


def _profile_from_values(slug: str, values: dict[str, str]) -> ServerProfile | None:
    def get(field_name: str) -> str:
        return values.get(f"{_PREFIX}{slug}_{field_name.upper()}", "")

    host = get("host")
    if not host:
        log.warning("профиль %s без HOST — пропускаю", slug)
        return None

    try:
        port = int(get("port") or 22)
    except ValueError:
        log.warning("профиль %s: некорректный PORT %r, беру 22", slug, get("port"))
        port = 22

    tags = [t.strip() for t in get("tags").split(",") if t.strip()]
    return ServerProfile(
        name=get("name") or slug.lower(),
        host=host,
        user=get("user") or "root",
        port=port,
        password=get("password"),
        key_file=get("key_file"),
        passphrase=get("passphrase"),
        auth=get("auth") or "auto",
        label=get("label"),
        domain=get("domain"),
        jump=get("jump"),
        tags=tags,
        added=get("added"),
        last_ok=get("last_ok"),
    )


def _read_raw(path: Path) -> tuple[dict[str, str], list[str]]:
    if not path.exists():
        return {}, []
    return envfile.parse(path.read_text(encoding="utf-8"))


def load(path: Path | None = None) -> dict[str, ServerProfile]:
    """Прочитать все профили. Ключ словаря — имя в нижнем регистре."""
    target = path or SERVERS_ENV
    with _lock:
        values, _ = _read_raw(target)

    slugs: list[str] = []
    for key in values:
        match = _KEY_RE.match(key)
        if match and match.group("slug") not in slugs:
            slugs.append(match.group("slug"))

    profiles: dict[str, ServerProfile] = {}
    for slug in slugs:
        profile = _profile_from_values(slug, values)
        if profile is None:
            continue
        profiles[profile.name.lower()] = profile
        redact.remember(profile.password, profile.passphrase)
    return profiles


def get(name: str, path: Path | None = None) -> ServerProfile | None:
    return load(path).get(name.strip().lower())


def validate(profiles: dict[str, ServerProfile]) -> list[str]:
    """
    Проверки, которые дешевле сделать до попытки коннекта.

    Возвращает список предупреждений — не исключение: один кривой профиль не
    повод сделать нерабочими остальные пять.
    """
    problems: list[str] = []
    seen: dict[tuple[str, str, int], str] = {}
    for name, profile in profiles.items():
        if not 1 <= profile.port <= 65535:
            problems.append(f"{name}: порт {profile.port} вне диапазона 1..65535")
        endpoint = (profile.host, profile.user, profile.port)
        if endpoint in seen:
            problems.append(
                f"{name}: тот же адрес, что и у {seen[endpoint]} ({profile.endpoint})"
            )
        else:
            seen[endpoint] = name
        if profile.jump and profile.jump.lower() not in profiles:
            problems.append(f"{name}: jump-хост {profile.jump!r} не найден в хранилище")
        if profile.key_file and not Path(profile.key_file).expanduser().exists():
            problems.append(f"{name}: файл ключа {profile.key_file} отсутствует")
    return problems


# ------------------------------------------------------------------- запись


def _render(profiles: dict[str, ServerProfile], foreign: dict[str, str]) -> str:
    pairs: list[tuple[str, str]] = []
    for key in sorted(foreign):
        pairs.append((key, foreign[key]))
    if foreign:
        pairs.append(("", ""))

    for name in sorted(profiles):
        profile = profiles[name]
        slug = slugify(profile.name)
        for field_name in _FIELDS:
            value = getattr(profile, field_name)
            if field_name == "tags":
                value = ",".join(value)
            elif field_name == "port":
                value = str(value)
            pairs.append((f"{_PREFIX}{slug}_{field_name.upper()}", value))
        pairs.append(("", ""))
    return envfile.render(pairs, header=_HEADER)


def _write_atomic(text: str, path: Path) -> None:
    """
    Атомарная запись с правами, выставленными в момент создания.

    ``O_EXCL`` заодно ловит параллельного писателя: лучше громкая ошибка, чем
    молча перетёртый файл с паролями.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    harden_permissions(tmp)
    if path.exists():
        # Файл вне git: потеря означает потерю всех паролей разом.
        backup = path.with_suffix(path.suffix + ".bak")
        backup.unlink(missing_ok=True)
        os.replace(path, backup)
    os.replace(tmp, path)
    harden_permissions(path)


def save(profile: ServerProfile, *, overwrite: bool = False,
         path: Path | None = None) -> ServerProfile:
    """
    Сохранить профиль. Перед записью перечитываем файл с диска, чтобы не
    затереть правку, сделанную руками или другим процессом.
    """
    target = path or SERVERS_ENV
    name = profile.name.strip().lower()
    if not name:
        raise StoreError("пустое имя сервера")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", name):
        raise StoreError(
            f"имя {profile.name!r} не годится: разрешены латиница, цифры, '.', '_', '-', "
            f"до 32 символов, первый — буква или цифра"
        )

    with _lock:
        values, _ = _read_raw(target)
        foreign = {k: v for k, v in values.items() if not _KEY_RE.match(k)}
        profiles = load(target)

        existing = profiles.get(name)
        if existing and not overwrite:
            if (existing.host, existing.user, existing.port) != (
                profile.host, profile.user, profile.port
            ):
                raise StoreError(
                    f"сервер {name!r} уже существует и указывает на "
                    f"{existing.endpoint}, а не на {profile.endpoint}. "
                    f"Передайте overwrite=true, если замена намеренная"
                )

        stamped = replace(
            profile,
            name=name,
            added=profile.added or (existing.added if existing else now_iso()),
        )
        profiles[name] = stamped
        _write_atomic(_render(profiles, foreign), target)

    redact.remember(stamped.password, stamped.passphrase)
    log.info("сохранён профиль %s (%s)", name, stamped.endpoint)
    return stamped


def save_many(new_profiles: list[ServerProfile], *, overwrite: bool = False,
              path: Path | None = None) -> list[str]:
    """Записать пачку профилей одной перезаписью файла (импорт)."""
    target = path or SERVERS_ENV
    written: list[str] = []
    with _lock:
        values, _ = _read_raw(target)
        foreign = {k: v for k, v in values.items() if not _KEY_RE.match(k)}
        profiles = load(target)
        for profile in new_profiles:
            name = profile.name.strip().lower()
            if name in profiles and not overwrite:
                continue
            profiles[name] = replace(
                profile, name=name, added=profile.added or now_iso()
            )
            written.append(name)
            redact.remember(profile.password, profile.passphrase)
        _write_atomic(_render(profiles, foreign), target)
    return written


def delete(name: str, path: Path | None = None) -> bool:
    target = path or SERVERS_ENV
    key = name.strip().lower()
    with _lock:
        values, _ = _read_raw(target)
        foreign = {k: v for k, v in values.items() if not _KEY_RE.match(k)}
        profiles = load(target)
        if key not in profiles:
            return False
        del profiles[key]
        _write_atomic(_render(profiles, foreign), target)
    log.info("удалён профиль %s", key)
    return True


def touch_last_ok(name: str, path: Path | None = None) -> None:
    """Отметить успешное подключение. Тихо игнорирует неизвестное имя."""
    target = path or SERVERS_ENV
    with _lock:
        profiles = load(target)
        profile = profiles.get(name.strip().lower())
        if profile is None:
            return
        values, _ = _read_raw(target)
        foreign = {k: v for k, v in values.items() if not _KEY_RE.match(k)}
        profiles[profile.name.lower()] = replace(profile, last_ok=now_iso())
        _write_atomic(_render(profiles, foreign), target)
