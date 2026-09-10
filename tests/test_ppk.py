"""
Разбор ключей PuTTY.

Незашифрованный ключ собирается прямо здесь, поэтому основной путь —
заголовки, блобы, MAC, пересборка в формат OpenSSH — проверяется без
внешних файлов.

Зашифрованный путь (Argon2id + AES-CBC) так проверить нельзя: собрать файл
своим же кодом и им же разобрать — значит проверить согласованность с самим
собой, а не с PuTTY. Поэтому он вынесен в тест на настоящем файле, который
включается переменными окружения:

    SSHM_TEST_PPK=/path/to/key.ppk SSHM_TEST_PPK_PASSPHRASE=... pytest
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from pathlib import Path

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ssh_mcp import ppk

REAL_PPK = Path(os.environ.get("SSHM_TEST_PPK") or "нет-такого-файла")
REAL_PHRASE = os.environ.get("SSHM_TEST_PPK_PASSPHRASE", "")


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _write_plain_ppk(path: Path, comment: str = "тестовый") -> ed25519.Ed25519PrivateKey:
    """Собрать незашифрованный .ppk версии 3 из свежего ключа Ed25519."""
    private = ed25519.Ed25519PrivateKey.generate()
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw_private = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_blob = _string(b"ssh-ed25519") + _string(raw_public)
    private_blob = _string(raw_private)

    payload = (
        _string(b"ssh-ed25519") + _string(b"none")
        + _string(comment.encode()) + _string(public_blob) + _string(private_blob)
    )
    mac = hmac.new(b"\x00" * 32, payload, hashlib.sha256).hexdigest()

    def lines(blob: bytes) -> list[str]:
        body = base64.b64encode(blob).decode()
        return [body[i : i + 64] for i in range(0, len(body), 64)]

    public_lines, private_lines = lines(public_blob), lines(private_blob)
    text = [
        "PuTTY-User-Key-File-3: ssh-ed25519",
        "Encryption: none",
        f"Comment: {comment}",
        f"Public-Lines: {len(public_lines)}",
        *public_lines,
        f"Private-Lines: {len(private_lines)}",
        *private_lines,
        f"Private-MAC: {mac}",
        "",
    ]
    path.write_text("\n".join(text), encoding="utf-8")
    return private


def test_reads_an_unencrypted_key(tmp_path):
    path = tmp_path / "plain.ppk"
    original = _write_plain_ppk(path)

    key = ppk.load(path)
    assert key.algorithm == "ssh-ed25519"
    assert key.comment == "тестовый"

    expected = original.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert key.public_blob.endswith(expected)


def test_public_key_line_matches_openssh_format(tmp_path):
    path = tmp_path / "plain.ppk"
    _write_plain_ppk(path, comment="метка")
    line = ppk.load(path).openssh_public()
    assert line.startswith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
    assert line.endswith("метка")


def test_converts_to_a_key_paramiko_can_use(tmp_path):
    source = tmp_path / "plain.ppk"
    _write_plain_ppk(source)
    key = ppk.load(source)

    converted = tmp_path / "converted"
    converted.write_bytes(ppk.to_openssh_private(key))
    loaded = paramiko.PKey.from_path(converted)
    assert loaded.get_name() == "ssh-ed25519"
    assert loaded.asbytes() == key.public_blob


def test_conversion_can_keep_the_key_encrypted(tmp_path):
    source = tmp_path / "plain.ppk"
    _write_plain_ppk(source)
    key = ppk.load(source)

    converted = tmp_path / "converted"
    converted.write_bytes(ppk.to_openssh_private(key, "фраза"))
    assert paramiko.PKey.from_path(converted, "фраза".encode()).asbytes() == key.public_blob
    with pytest.raises(Exception):
        paramiko.PKey.from_path(converted)


def test_corrupted_mac_is_detected(tmp_path):
    path = tmp_path / "plain.ppk"
    _write_plain_ppk(path)
    text = path.read_text(encoding="utf-8").replace("Private-MAC: ", "Private-MAC: ff")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ppk.PPKBadPassphrase):
        ppk.load(path)


def test_encrypted_key_without_passphrase_is_reported(tmp_path):
    path = tmp_path / "enc.ppk"
    _write_plain_ppk(path)
    text = path.read_text(encoding="utf-8").replace("Encryption: none", "Encryption: aes256-cbc")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ppk.PPKBadPassphrase, match="нужна парольная фраза"):
        ppk.load(path, "")


def test_rejects_a_file_that_is_not_ppk(tmp_path):
    path = tmp_path / "nope.ppk"
    path.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n", encoding="utf-8")
    with pytest.raises(ppk.PPKError):
        ppk.load(path)


# --- зашифрованный путь: только на настоящем файле от PuTTY

needs_real = pytest.mark.skipif(
    not REAL_PPK.exists() or not REAL_PHRASE,
    reason="задайте SSHM_TEST_PPK и SSHM_TEST_PPK_PASSPHRASE",
)


@needs_real
def test_real_encrypted_key_decrypts():
    key = ppk.load(REAL_PPK, REAL_PHRASE)
    assert key.public_blob
    assert key.algorithm.startswith(("ssh-", "ecdsa-"))


@needs_real
def test_real_key_wrong_passphrase_is_caught_by_the_mac():
    """MAC отличает неверную фразу от испорченного файла — это разные беды."""
    with pytest.raises(ppk.PPKBadPassphrase):
        ppk.load(REAL_PPK, REAL_PHRASE + "-мимо")


@needs_real
def test_real_key_round_trips_through_openssh(tmp_path):
    key = ppk.load(REAL_PPK, REAL_PHRASE)
    path = tmp_path / "converted"
    path.write_bytes(ppk.to_openssh_private(key, REAL_PHRASE))
    assert paramiko.PKey.from_path(path, REAL_PHRASE.encode()).asbytes() == key.public_blob
