"""Расписание раундовых ключей (учебная схема)."""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable


def validate_key_hex(key_hex: str) -> list[int]:
    key_hex = key_hex.strip().replace(" ", "")
    if len(key_hex) != 16 or not all(c.lower() in "0123456789abcdef" for c in key_hex):
        raise ValueError("Ключ должен быть 16 hex-символов (0-9, a-f)")
    return list(bytes.fromhex(key_hex))


@lru_cache(maxsize=1024)
def expand_round_keys(key_tuple: tuple[int, ...], num_rounds: int) -> tuple[tuple[int, ...], ...]:
    key = list(key_tuple)
    round_keys: list[list[int]] = []
    for r in range(2 * num_rounds + 1):
        subkey = [(key[i] + (r * 8 + i)) % 256 for i in range(8)]
        round_keys.append(subkey)
    return tuple(tuple(k) for k in round_keys)


class RoundKeySchedule:
    """Единая точка расширения ключа (SRP: только расписание ключей)."""

    def expand(self, master_key_bytes: Iterable[int], num_rounds: int) -> tuple[tuple[int, ...], ...]:
        t = tuple(int(b) % 256 for b in master_key_bytes)
        if len(t) != 8:
            raise ValueError("Мастер-ключ должен быть ровно 8 байт")
        return expand_round_keys(t, num_rounds)
