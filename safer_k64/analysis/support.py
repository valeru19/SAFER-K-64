"""Общие утилиты для атак."""

from __future__ import annotations

from typing import Iterable

from safer_k64.cipher.primitives import linear_transform
from safer_k64.cipher.tables import get_tables
from safer_k64.domain.models import Block8


def pack_key_tuple(key_bytes: Iterable[int]) -> tuple[int, ...]:
    t = tuple(int(b) % 256 for b in key_bytes)
    if len(t) != 8:
        raise ValueError("Ключ должен быть 8 байт")
    return t


def build_differential_characteristic(num_rounds: int) -> tuple[list[int], list[int], float]:
    if num_rounds > 4:
        return [0] * 8, [0] * 8, 0.0
    diff_table = get_tables().diff_table
    best_diff_in = 1
    best_diff_out = max(range(256), key=lambda x: diff_table[best_diff_in][x])
    probability = diff_table[best_diff_in][best_diff_out] / 256
    diff_in = [best_diff_in] + [0] * 7
    diff_out = [best_diff_out] + [0] * 7
    for r in range(num_rounds):
        diff_out = linear_transform(diff_out)
        probability *= 0.5
        if r < num_rounds - 1:
            diff_in = diff_out
            diff_out = [max(range(256), key=lambda x: diff_table[diff_in[0]][x])] + [0] * 7
            probability *= diff_table[diff_in[0]][diff_out[0]] / 256
    return diff_in, diff_out, probability
