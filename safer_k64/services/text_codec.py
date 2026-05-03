"""Кодирование текста в блоки 8 байт и обратно (PKCS#7-подобное дополнение)."""

from __future__ import annotations

from safer_k64.domain.models import Block8


def utf8_to_blocks(text: str) -> list[Block8]:
    data = text.encode("utf-8")
    pad = 8 - (len(data) % 8)
    if pad == 0:
        pad = 8
    padded = data + bytes([pad] * pad)
    return [list(padded[i : i + 8]) for i in range(0, len(padded), 8)]


def blocks_to_utf8(blocks: list[Block8]) -> str:
    raw = bytes(b for block in blocks for b in block)
    if not raw:
        return ""
    pad_len = raw[-1]
    if 1 <= pad_len <= 8 and all(raw[-i] == pad_len for i in range(1, pad_len + 1)):
        raw = raw[:-pad_len]
    return raw.decode("utf-8", errors="replace")
