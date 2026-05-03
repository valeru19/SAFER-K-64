"""Примитивы раунда: сложение ключа, S-блок, линейный слой."""

from __future__ import annotations

from safer_k64.domain.models import Block8


def add_key(data: Block8, key: Block8) -> Block8:
    return [(d + k) % 256 for d, k in zip(data, key)]


def sub_key(data: Block8, key: Block8) -> Block8:
    return [(d - k) % 256 for d, k in zip(data, key)]


def apply_sbox(data: Block8, sbox: tuple[int, ...]) -> Block8:
    return [sbox[d % 256] for d in data]


def linear_transform(data: Block8) -> Block8:
    """Обратимая PHT-пара mod 256 (det [[2,1],[1,1]] = 1)."""
    result = list(data)
    for i in range(0, 8, 2):
        x, y = result[i], result[i + 1]
        nx = (2 * x + y) % 256
        ny = (x + y) % 256
        result[i], result[i + 1] = nx, ny
    temp = result.copy()
    result[0], result[1], result[2], result[3] = temp[0], temp[4], temp[2], temp[6]
    result[4], result[5], result[6], result[7] = temp[1], temp[5], temp[3], temp[7]
    return result


def inverse_linear_transform(data: Block8) -> Block8:
    result = list(data)
    temp = result.copy()
    result[0], result[4], result[2], result[6] = temp[0], temp[1], temp[2], temp[3]
    result[1], result[5], result[3], result[7] = temp[4], temp[5], temp[6], temp[7]
    for i in range(0, 8, 2):
        nx, ny = result[i], result[i + 1]
        x = (nx - ny) % 256
        y = (ny - x) % 256
        result[i], result[i + 1] = x, y
    return result
