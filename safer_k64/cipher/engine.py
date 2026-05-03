"""Движок блочного шифра 8 байт (учебный SAFER K-64-подобный)."""

from __future__ import annotations

from typing import Protocol

from safer_k64.cipher.primitives import (
    add_key,
    apply_sbox,
    inverse_linear_transform,
    linear_transform,
    sub_key,
)
from safer_k64.cipher.tables import get_tables
from safer_k64.domain.models import Block8


class ICipherEngine(Protocol):
    def encrypt_block(self, block: Block8, round_keys: tuple[tuple[int, ...], ...], num_rounds: int) -> Block8: ...

    def decrypt_block(self, block: Block8, round_keys: tuple[tuple[int, ...], ...], num_rounds: int) -> Block8: ...


class SaferK64Engine:
    """Реализация шифрования/дешифрования одного блока."""

    def __init__(self) -> None:
        t = get_tables()
        self._exp = t.exp_sbox
        self._log = t.log_sbox

    def encrypt_block(self, block: Block8, round_keys: tuple[tuple[int, ...], ...], num_rounds: int) -> Block8:
        data = block[:]
        for r in range(num_rounds):
            data = add_key(data, list(round_keys[2 * r]))
            data = apply_sbox(data, self._exp)
            data = add_key(data, list(round_keys[2 * r + 1]))
            data = linear_transform(data)
        data = add_key(data, list(round_keys[2 * num_rounds]))
        return data

    def decrypt_block(self, block: Block8, round_keys: tuple[tuple[int, ...], ...], num_rounds: int) -> Block8:
        data = block[:]
        data = sub_key(data, list(round_keys[2 * num_rounds]))
        for r in range(num_rounds - 1, -1, -1):
            data = inverse_linear_transform(data)
            data = sub_key(data, list(round_keys[2 * r + 1]))
            data = apply_sbox(data, self._log)
            data = sub_key(data, list(round_keys[2 * r]))
        return data
