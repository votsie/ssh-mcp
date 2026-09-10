"""
Чтение приватных ключей PuTTY (.ppk) версий 2 и 3.

Paramiko формат PuTTY не понимает, а `puttygen` есть далеко не везде — на
Windows его обычно и нет. Поэтому разбираем сами и отдаём ключ в виде,
пригодном для OpenSSH.

Формат описан в документации PuTTY. Существенное: в версии 3 ключ шифрования
выводится из парольной фразы через Argon2, в версии 2 — через SHA-1, и MAC
считается по строго заданной склейке полей. MAC проверяем всегда: он отличает
неверную фразу от испорченного файла, а это разные беды с разным лечением.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class PPKError(RuntimeError):
    """Файл .ppk не разобрался."""


class PPKBadPassphrase(PPKError):
    """MAC не сошёлся — почти всегда это неверная парольная фраза."""


@dataclass
class PPKKey:
    algorithm: str
    comment: str
    public_blob: bytes
    private_blob: bytes

    def openssh_public(self) -> str:
        body = base64.b64encode(self.public_blob).decode()
        return f"{self.algorithm} {body} {self.comment}".strip()


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _read_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", blob[offset : offset + 4])
    start = offset + 4
    return blob[start : start + length], start + length


def _parse_headers(text: str) -> tuple[dict[str, str], dict[str, bytes]]:
    headers: dict[str, str] = {}
    blobs: dict[str, bytes] = {}
    lines = text.replace("\r\n", "\n").split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if ":" not in line:
            raise PPKError(f"неожиданная строка в .ppk: {line[:40]!r}")
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key.endswith("-Lines"):
            count = int(value)
            body = "".join(lines[index + 1 : index + 1 + count])
            blobs[key[: -len("-Lines")]] = base64.b64decode(body)
            index += 1 + count
            continue
        headers[key] = value
        index += 1
    return headers, blobs


def _derive_v3(passphrase: bytes, headers: dict[str, str]) -> tuple[bytes, bytes, bytes]:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    flavour = headers.get("Key-Derivation", "Argon2id")
    if flavour != "Argon2id":
        raise PPKError(f"вариант Argon2 {flavour!r} не поддерживается")

    material = Argon2id(
        salt=bytes.fromhex(headers["Argon2-Salt"]),
        length=80,  # 32 байта ключа + 16 IV + 32 ключа MAC
        iterations=int(headers["Argon2-Passes"]),
        lanes=int(headers["Argon2-Parallelism"]),
        memory_cost=int(headers["Argon2-Memory"]),
    ).derive(passphrase)
    return material[:32], material[32:48], material[48:80]


def _derive_v2(passphrase: bytes) -> tuple[bytes, bytes, bytes]:
    # Версия 2: ключ шифрования — две порции SHA-1, IV нулевой, ключ MAC —
    # SHA-1 от фиксированной строки и фразы.
    parts = [
        hashlib.sha1(struct.pack(">I", index) + passphrase).digest()
        for index in (0, 1)
    ]
    cipher_key = (parts[0] + parts[1])[:32]
    mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + passphrase).digest()
    return cipher_key, b"\x00" * 16, mac_key


def load(path: str | Path, passphrase: str = "") -> PPKKey:
    """Разобрать .ppk и вернуть алгоритм, комментарий и оба блоба."""
    source = Path(path).expanduser()
    headers, blobs = _parse_headers(source.read_text(encoding="utf-8"))

    version = None
    for candidate in (2, 3):
        if f"PuTTY-User-Key-File-{candidate}" in headers:
            version = candidate
            algorithm = headers[f"PuTTY-User-Key-File-{candidate}"]
            break
    if version is None:
        raise PPKError("это не файл PuTTY версии 2 или 3")

    encryption = headers.get("Encryption", "none")
    comment = headers.get("Comment", "")
    public_blob = blobs.get("Public", b"")
    private_blob = blobs.get("Private", b"")

    if encryption == "none":
        cipher_key = iv = b""
        mac_key = (
            hashlib.sha1(b"putty-private-key-file-mac-key").digest()
            if version == 2 else b"\x00" * 32
        )
    elif encryption == "aes256-cbc":
        if not passphrase:
            raise PPKBadPassphrase("ключ зашифрован, нужна парольная фраза")
        secret = passphrase.encode("utf-8")
        cipher_key, iv, mac_key = (
            _derive_v3(secret, headers) if version == 3 else _derive_v2(secret)
        )
        decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        private_blob = decryptor.update(private_blob) + decryptor.finalize()
    else:
        raise PPKError(f"шифрование {encryption!r} не поддерживается")

    expected = headers.get("Private-MAC", "")
    payload = (
        _ssh_string(algorithm.encode())
        + _ssh_string(encryption.encode())
        + _ssh_string(comment.encode())
        + _ssh_string(public_blob)
        + _ssh_string(private_blob)
    )
    digest = hashlib.sha256 if version == 3 else hashlib.sha1
    actual = hmac.new(mac_key, payload, digest).hexdigest()
    if expected and not hmac.compare_digest(actual, expected):
        raise PPKBadPassphrase(
            "контрольная сумма не сошлась — неверная парольная фраза "
            "либо повреждённый файл"
        )

    return PPKKey(algorithm, comment, public_blob, private_blob)


def to_openssh_private(key: PPKKey, passphrase: str = "") -> bytes:
    """Пересобрать ключ в приватный файл формата OpenSSH."""
    if key.algorithm == "ssh-ed25519":
        seed, _ = _read_string(key.private_blob, 0)
        private = ed25519.Ed25519PrivateKey.from_private_bytes(seed[-32:])
    elif key.algorithm == "ssh-rsa":
        _, offset = _read_string(key.public_blob, 0)
        exponent_bytes, offset = _read_string(key.public_blob, offset)
        modulus_bytes, _ = _read_string(key.public_blob, offset)
        public_exponent = int.from_bytes(exponent_bytes, "big")
        modulus = int.from_bytes(modulus_bytes, "big")

        pos = 0
        private_exponent_bytes, pos = _read_string(key.private_blob, pos)
        prime1_bytes, pos = _read_string(key.private_blob, pos)
        prime2_bytes, pos = _read_string(key.private_blob, pos)
        private_exponent = int.from_bytes(private_exponent_bytes, "big")
        prime1 = int.from_bytes(prime1_bytes, "big")
        prime2 = int.from_bytes(prime2_bytes, "big")
        private = rsa.RSAPrivateNumbers(
            p=prime1,
            q=prime2,
            d=private_exponent,
            dmp1=rsa.rsa_crt_dmp1(private_exponent, prime1),
            dmq1=rsa.rsa_crt_dmq1(private_exponent, prime2),
            iqmp=rsa.rsa_crt_iqmp(prime1, prime2),
            public_numbers=rsa.RSAPublicNumbers(public_exponent, modulus),
        ).private_key()
    elif key.algorithm.startswith("ecdsa-sha2-"):
        curves = {
            "ecdsa-sha2-nistp256": ec.SECP256R1(),
            "ecdsa-sha2-nistp384": ec.SECP384R1(),
            "ecdsa-sha2-nistp521": ec.SECP521R1(),
        }
        curve = curves.get(key.algorithm)
        if curve is None:
            raise PPKError(f"кривая {key.algorithm!r} не поддерживается")
        secret, _ = _read_string(key.private_blob, 0)
        private = ec.derive_private_key(int.from_bytes(secret, "big"), curve)
    else:
        raise PPKError(f"алгоритм {key.algorithm!r} не поддерживается")

    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase else serialization.NoEncryption()
    )
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption,
    )
