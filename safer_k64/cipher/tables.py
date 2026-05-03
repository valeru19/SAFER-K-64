"""S-блоки и вспомогательные таблицы (ленивая инициализация)."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class SBoxTables:
    exp_sbox: tuple[int, ...]
    log_sbox: tuple[int, ...]
    diff_table: tuple[tuple[int, ...], ...]
    linear_table: tuple[tuple[int, ...], ...]


_lock = Lock()
_tables: SBoxTables | None = None

BASE = 45
MOD = 257


def _build_tables() -> SBoxTables:
    exp = [0] * 256
    log = [0] * 256
    exp[0] = 1
    used = {1}
    for i in range(1, 256):
        val = (exp[i - 1] * BASE) % MOD % 256
        while val in used:
            val = (val + 1) % 256
        exp[i] = val
        used.add(val)
    for i in range(256):
        log[exp[i]] = i

    diff = [[0] * 256 for _ in range(256)]
    for x1 in range(256):
        for x2 in range(256):
            diff_in = (x1 - x2) % 256
            diff_out = (exp[x1] - exp[x2]) % 256
            diff[diff_in][diff_out] += 1

    linear = [[0] * 256 for _ in range(256)]
    for x in range(256):
        for input_mask in range(256):
            for output_mask in range(256):
                if bin(x & input_mask).count("1") % 2 == bin(exp[x] & output_mask).count("1") % 2:
                    linear[input_mask][output_mask] += 1

    return SBoxTables(
        exp_sbox=tuple(exp),
        log_sbox=tuple(log),
        diff_table=tuple(tuple(row) for row in diff),
        linear_table=tuple(tuple(row) for row in linear),
    )


def get_tables() -> SBoxTables:
    global _tables
    with _lock:
        if _tables is None:
            _tables = _build_tables()
        return _tables
