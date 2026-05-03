"""Разбор и форматирование hex для блоков."""

from __future__ import annotations

from safer_k64.domain.models import Block8


def normalize_hex(s: str) -> str:
    return "".join(c for c in s.strip() if c.lower() in "0123456789abcdef")


def blocks_from_hex(s: str) -> list[Block8]:
    h = normalize_hex(s)
    if len(h) % 16 != 0:
        raise ValueError("Длина hex шифротекста должна быть кратна 16 символам (8 байт на блок).")
    return [list(bytes.fromhex(h[i : i + 16])) for i in range(0, len(h), 16)]


def blocks_to_hex(blocks: list[Block8]) -> str:
    return "".join(bytes(b).hex() for b in blocks)
