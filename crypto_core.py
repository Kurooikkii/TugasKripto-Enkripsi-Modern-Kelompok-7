"""Password-based encryption helpers using authenticated encryption."""

from __future__ import annotations

import struct
import secrets
import base64
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

Algorithm = Literal["AES-256-GCM", "ChaCha20-Poly1305"]

MAGIC = b"ENK1"
_HEADER = struct.Struct("!4sB16s12s")
_ALGORITHM_IDS: dict[Algorithm, int] = {
    "AES-256-GCM": 1,
    "ChaCha20-Poly1305": 2,
}
_ID_ALGORITHMS = {value: key for key, value in _ALGORITHM_IDS.items()}
_KEY_LENGTH = 32
_SALT_LENGTH = 16
_NONCE_LENGTH = 12
_CHUNK_SIZE = 64 * 1024
_FILE_MAGIC = b"ENK2"
_FILE_HEADER = struct.Struct("!4sB16sQ")
_FILE_RECORD = struct.Struct("!12sI")


def _cipher_for(algorithm: Algorithm, key: bytes) -> AESGCM | ChaCha20Poly1305:
    if algorithm == "AES-256-GCM":
        return AESGCM(key)
    if algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"Algoritma tidak didukung: {algorithm}")


def _decode_field(data: dict, field: str) -> bytes:
    try:
        value = base64.b64decode(data[field], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Field {field!r} tidak valid atau tidak ditemukan.") from exc
    return value


def _decrypt_authenticated(cipher: AESGCM | ChaCha20Poly1305, nonce: bytes,
                           ciphertext: bytes, associated_data: bytes) -> bytes:
    try:
        return cipher.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise ValueError("Password salah atau data telah diubah.") from exc


def _derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password harus berupa string yang tidak kosong.")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=_KEY_LENGTH,
        type=Type.ID,
    )


def encrypt(data: bytes, password: str, algorithm: Algorithm = "AES-256-GCM") -> bytes:
    """Encrypt bytes and return a self-contained authenticated payload."""
    if not isinstance(data, bytes):
        raise TypeError("Data harus berupa bytes.")
    if algorithm not in _ALGORITHM_IDS:
        raise ValueError(f"Algoritma tidak didukung: {algorithm}")

    salt = secrets.token_bytes(_SALT_LENGTH)
    nonce = secrets.token_bytes(_NONCE_LENGTH)
    key = _derive_key(password, salt)
    header = _HEADER.pack(MAGIC, _ALGORITHM_IDS[algorithm], salt, nonce)

    cipher = _cipher_for(algorithm, key)
    return header + cipher.encrypt(nonce, data, header)


def decrypt(payload: bytes, password: str) -> bytes:
    """Decrypt a payload produced by :func:`encrypt`."""
    if not isinstance(payload, bytes):
        raise TypeError("Payload harus berupa bytes.")
    if len(payload) <= _HEADER.size:
        raise ValueError("Payload tidak lengkap atau formatnya tidak valid.")

    header = payload[: _HEADER.size]
    magic, algorithm_id, salt, nonce = _HEADER.unpack(header)
    if magic != MAGIC:
        raise ValueError("Format payload tidak dikenal.")
    try:
        algorithm = _ID_ALGORITHMS[algorithm_id]
    except KeyError as exc:
        raise ValueError("Algoritma pada payload tidak didukung.") from exc

    key = _derive_key(password, salt)
    cipher = _cipher_for(algorithm, key)
    return _decrypt_authenticated(cipher, nonce, payload[_HEADER.size :], header)


def _encrypt_dict(plaintext: bytes, password: str, algorithm: Algorithm) -> dict:
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext harus berupa bytes.")
    salt = secrets.token_bytes(_SALT_LENGTH)
    nonce = secrets.token_bytes(_NONCE_LENGTH)
    key = _derive_key(password, salt)
    cipher = _cipher_for(algorithm, key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _decrypt_dict(data: dict, password: str, algorithm: Algorithm) -> bytes:
    if not isinstance(data, dict):
        raise TypeError("Data harus berupa dictionary.")
    salt = _decode_field(data, "salt")
    nonce = _decode_field(data, "nonce")
    ciphertext = _decode_field(data, "ciphertext")
    if len(salt) != _SALT_LENGTH or len(nonce) != _NONCE_LENGTH:
        raise ValueError("Panjang salt atau nonce tidak valid.")
    key = _derive_key(password, salt)
    return _decrypt_authenticated(_cipher_for(algorithm, key), nonce, ciphertext, None)


def encrypt_aes_gcm(plaintext: bytes, password: str) -> dict:
    """Encrypt bytes with AES-256-GCM and return base64 fields."""
    return _encrypt_dict(plaintext, password, "AES-256-GCM")


def decrypt_aes_gcm(data: dict, password: str) -> bytes:
    """Decrypt the base64 fields produced by :func:`encrypt_aes_gcm`."""
    return _decrypt_dict(data, password, "AES-256-GCM")


def encrypt_chacha20(plaintext: bytes, password: str) -> dict:
    """Encrypt bytes with ChaCha20-Poly1305 and return base64 fields."""
    return _encrypt_dict(plaintext, password, "ChaCha20-Poly1305")


def decrypt_chacha20(data: dict, password: str) -> bytes:
    """Decrypt the base64 fields produced by :func:`encrypt_chacha20`."""
    return _decrypt_dict(data, password, "ChaCha20-Poly1305")


def _file_algorithm(value: str) -> Algorithm:
    aliases = {
        "aes": "AES-256-GCM",
        "aes-gcm": "AES-256-GCM",
        "aes-256-gcm": "AES-256-GCM",
        "chacha20": "ChaCha20-Poly1305",
        "chacha20-poly1305": "ChaCha20-Poly1305",
    }
    try:
        return aliases[value.lower()]
    except (AttributeError, KeyError) as exc:
        raise ValueError("Algoritma harus AES-256-GCM atau ChaCha20-Poly1305.") from exc


def encrypt_file(input_path: str, output_path: str, password: str, algorithm: str) -> None:
    """Encrypt a file in authenticated 64 KiB records."""
    selected = _file_algorithm(algorithm)
    input_file = Path(input_path)
    file_size = input_file.stat().st_size
    salt = secrets.token_bytes(_SALT_LENGTH)
    key = _derive_key(password, salt)
    cipher = _cipher_for(selected, key)
    header = _FILE_HEADER.pack(_FILE_MAGIC, _ALGORITHM_IDS[selected], salt, file_size)

    with input_file.open("rb") as source, Path(output_path).open("wb") as target:
        target.write(header)
        chunk_number = 0
        while chunk := source.read(_CHUNK_SIZE):
            nonce = secrets.token_bytes(_NONCE_LENGTH)
            associated_data = header + struct.pack("!Q", chunk_number)
            ciphertext = cipher.encrypt(nonce, chunk, associated_data)
            target.write(_FILE_RECORD.pack(nonce, len(ciphertext)))
            target.write(ciphertext)
            chunk_number += 1


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a file written by :func:`encrypt_file` record by record."""
    with Path(input_path).open("rb") as source:
        header = source.read(_FILE_HEADER.size)
        if len(header) != _FILE_HEADER.size:
            raise ValueError("File terenkripsi tidak lengkap.")
        magic, algorithm_id, salt, original_size = _FILE_HEADER.unpack(header)
        if magic != _FILE_MAGIC:
            raise ValueError("Format file terenkripsi tidak dikenal.")
        try:
            algorithm = _ID_ALGORITHMS[algorithm_id]
        except KeyError as exc:
            raise ValueError("Algoritma pada file tidak didukung.") from exc

        cipher = _cipher_for(algorithm, _derive_key(password, salt))
        written = 0
        chunk_number = 0
        with Path(output_path).open("wb") as target:
            while True:
                record_header = source.read(_FILE_RECORD.size)
                if not record_header:
                    break
                if len(record_header) != _FILE_RECORD.size:
                    raise ValueError("File terenkripsi terpotong.")
                nonce, ciphertext_size = _FILE_RECORD.unpack(record_header)
                ciphertext = source.read(ciphertext_size)
                if len(ciphertext) != ciphertext_size:
                    raise ValueError("File terenkripsi terpotong.")
                associated_data = header + struct.pack("!Q", chunk_number)
                plaintext = _decrypt_authenticated(cipher, nonce, ciphertext, associated_data)
                target.write(plaintext)
                written += len(plaintext)
                chunk_number += 1

        if written != original_size:
            raise ValueError("Ukuran file hasil dekripsi tidak sesuai; file mungkin diubah.")


__all__ = [
    "Algorithm",
    "decrypt",
    "decrypt_aes_gcm",
    "decrypt_chacha20",
    "decrypt_file",
    "encrypt",
    "encrypt_aes_gcm",
    "encrypt_chacha20",
    "encrypt_file",
]
