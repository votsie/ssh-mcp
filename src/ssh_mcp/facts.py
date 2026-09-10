"""
Проба сервера при подключении и подсказка имени для нового сервера.

Проба — одна команда, а не десяток: каждый вызов ``run`` это отдельный канал и
лишний круг по сети. Всё закрыто ``2>/dev/null``, а разбор терпит отсутствие
любого поля: упавшая проба не должна ронять успешное подключение.
"""

from __future__ import annotations

import re
import socket

from .connection import Connection
from .config import log

PROBE = r"""
echo "__H__$(hostname -s 2>/dev/null)"
echo "__F__$(hostname -f 2>/dev/null)"
echo "__K__$(uname -sr 2>/dev/null)"
echo "__A__$(uname -m 2>/dev/null)"
echo "__O__$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
echo "__C__$(nproc 2>/dev/null)"
echo "__M__$(free -m 2>/dev/null | awk '/Mem:/{print $2}')"
echo "__D__$(df -h / 2>/dev/null | tail -1 | awk '{print $3"/"$2}')"
echo "__Z__$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"
echo "__U__$(uptime -p 2>/dev/null)"
echo "__S__$(command -v docker nginx apache2 caddy xray sing-box wg x-ui 3x-ui 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\n' ' ')"
echo "__P__$(ss -lntH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | head -20 | tr '\n' ' ')"
"""

_TAGS = {
    "__H__": "hostname", "__F__": "fqdn", "__K__": "kernel", "__A__": "arch",
    "__O__": "os", "__C__": "cpus", "__M__": "mem_mb", "__D__": "disk_root",
    "__Z__": "timezone", "__U__": "uptime", "__S__": "software", "__P__": "ports",
}

# Часовой пояс — бесплатный источник страны: он уже есть в пробе, не требует
# ни внешнего сервиса, ни лишнего запроса, и даёт ровно ту схему имён
# (ru/nl/usa), которой пользователь уже пользуется.
_TZ_COUNTRY = {
    "Europe/Moscow": "ru", "Europe/Kaliningrad": "ru", "Asia/Yekaterinburg": "ru",
    "Asia/Novosibirsk": "ru", "Asia/Omsk": "ru", "Asia/Krasnoyarsk": "ru",
    "Asia/Irkutsk": "ru", "Asia/Vladivostok": "ru",
    "Europe/Amsterdam": "nl", "Europe/Berlin": "de", "Europe/Paris": "fr",
    "Europe/London": "uk", "Europe/Stockholm": "se", "Europe/Helsinki": "fi",
    "Europe/Warsaw": "pl", "Europe/Prague": "cz", "Europe/Vienna": "at",
    "Europe/Zurich": "ch", "Europe/Madrid": "es", "Europe/Rome": "it",
    "Europe/Kyiv": "ua", "Europe/Kiev": "ua", "Europe/Riga": "lv",
    "Europe/Vilnius": "lt", "Europe/Tallinn": "ee", "Europe/Belgrade": "rs",
    "Europe/Bucharest": "ro", "Europe/Sofia": "bg", "Europe/Istanbul": "tr",
    "Asia/Tokyo": "jp", "Asia/Singapore": "sg", "Asia/Hong_Kong": "hk",
    "Asia/Seoul": "kr", "Asia/Dubai": "ae", "Asia/Tel_Aviv": "il",
    "Australia/Sydney": "au", "America/Sao_Paulo": "br", "Africa/Johannesburg": "za",
    "Asia/Almaty": "kz", "Asia/Tbilisi": "ge", "Asia/Yerevan": "am",
}

# Имена, по которым сервер не отличить от тысячи других.
_GENERIC = {
    "localhost", "vps", "server", "srv", "debian", "ubuntu", "linux", "centos",
    "fedora", "alma", "rocky", "template", "vm", "host", "cloud", "test",
}


def probe(conn: Connection) -> dict:
    """Собрать факты о сервере. Никогда не бросает исключение."""
    facts: dict = {}
    try:
        result = conn.run(PROBE, timeout=25)
    except Exception as exc:
        log.warning("проба %s не удалась: %s", conn.profile.name, exc)
        return facts

    for line in result.stdout.splitlines():
        for marker, key in _TAGS.items():
            if line.startswith(marker):
                value = line[len(marker):].strip()
                if value:
                    facts[key] = value
                break

    for key in ("cpus", "mem_mb"):
        if key in facts:
            try:
                facts[key] = int(facts[key])
            except ValueError:
                facts.pop(key)

    if "software" in facts:
        facts["software"] = sorted(set(facts["software"].split()))
    if "ports" in facts:
        facts["ports"] = [int(p) for p in facts["ports"].split() if p.isdigit()]
    return facts


def _clean(candidate: str) -> str:
    candidate = re.sub(r"[^a-z0-9-]", "-", candidate.lower()).strip("-")
    candidate = re.sub(r"-{2,}", "-", candidate)
    return candidate[:16].rstrip("-")


def _reverse_dns(host: str) -> str | None:
    try:
        name = socket.gethostbyaddr(host)[0]
    except (OSError, socket.herror):
        return None
    label = name.split(".")[0]
    # PTR вида 250-19-56-72.provider.net — это переписанный тот же адрес,
    # именем сервера он быть не может.
    digits = set(re.findall(r"\d+", host))
    if digits and digits.issubset(set(re.findall(r"\d+", label))):
        return None
    return label


def suggest_names(host: str, facts: dict, taken: set[str]) -> list[str]:
    """
    Предложить имена для нового сервера, от осмысленных к запасным.

    Порядок: собственное имя хоста, обратный DNS, код страны по часовому
    поясу со свободным индексом, и наконец адрес.
    """
    candidates: list[str] = []

    hostname = facts.get("hostname", "")
    if hostname and _clean(hostname) not in _GENERIC and not re.fullmatch(r"[0-9a-f]{8,}", hostname):
        candidates.append(_clean(hostname))

    ptr = _reverse_dns(host)
    if ptr and _clean(ptr) not in _GENERIC:
        candidates.append(_clean(ptr))

    country = _TZ_COUNTRY.get(facts.get("timezone", ""))
    if country:
        for index in range(1, 100):
            candidate = f"{country}{index}"
            if candidate not in taken:
                candidates.append(candidate)
                break

    last_octet = host.rsplit(".", 1)[-1]
    if last_octet.isdigit():
        candidates.append(f"srv-{last_octet}")
    candidates.append(_clean(host) or "server")

    result: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in taken and candidate not in result:
            result.append(candidate)
    return result[:4]


def digest(facts: dict) -> str:
    """Одна строка для списка серверов — чтобы не заливать контекст."""
    parts = [facts.get("os", ""), facts.get("kernel", "")]
    if facts.get("cpus"):
        parts.append(f"{facts['cpus']} CPU")
    if facts.get("mem_mb"):
        parts.append(f"{facts['mem_mb']} МБ")
    if facts.get("software"):
        parts.append(", ".join(facts["software"][:4]))
    return " · ".join(p for p in parts if p)
