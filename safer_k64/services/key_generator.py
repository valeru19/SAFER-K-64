"""Генерация ключей для демонстрации и тестов."""

from __future__ import annotations

import secrets


class KeyGeneratorService:
    def random_key_hex(self) -> str:
        """Случайный 64-битный ключ (16 hex-символов)."""
        return secrets.token_hex(8)

    def uniform_byte_key_hex(self, byte_val: int | None = None) -> str:
        """«Слабый» демо-ключ: все 8 байт одинаковы (перебор 256 вариантов)."""
        b = secrets.randbelow(256) if byte_val is None else int(byte_val) % 256
        return bytes([b] * 8).hex()
