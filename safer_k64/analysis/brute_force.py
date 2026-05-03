"""Перебор мастер-ключа: гарантированно работает для «равномерного» ключа; иначе — ограниченный перебор."""

from __future__ import annotations

import time

from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.domain.models import AnalysisResult, AttackContext


def _key_from_index(i: int) -> tuple[int, ...]:
    return tuple((i >> (8 * (7 - j))) & 0xFF for j in range(8))


class UniformByteKeyBruteForceAttack:
    """Перебор ключей вида (b,b,b,b,b,b,b,b) — 256 вариантов."""

    id = "brute_uniform"
    title = "Перебор равномерного ключа (8× один байт)"

    def __init__(self, deps: CryptoAnalysisDependencies) -> None:
        self._deps = deps

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if not ctx.plaintext_blocks or not ctx.ciphertext_blocks:
            return self._fail("Нужны хотя бы один блок P и C.", t0)

        p, c = ctx.plaintext_blocks[0], ctx.ciphertext_blocks[0]
        eng = self._deps.engine
        sch = self._deps.schedule
        for b in range(256):
            key = tuple([b] * 8)
            rk = sch.expand(key, ctx.num_rounds)
            if eng.encrypt_block(p, rk, ctx.num_rounds) == c:
                elapsed = time.perf_counter() - t0
                return AnalysisResult(
                    attack_id=self.id,
                    title=self.title,
                    success=True,
                    message="Ключ найден полным перебором слабого класса (256 вариантов).",
                    recovered_key_hex=bytes(key).hex(),
                    elapsed_seconds=elapsed,
                    details=f"Байт ключа: {b}",
                    metadata={"candidates": b + 1, "space_size": 256},
                )
        elapsed = time.perf_counter() - t0
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message="Ключ не из класса «все байты равны».",
            elapsed_seconds=elapsed,
            metadata={"candidates": 256, "space_size": 256},
        )

    def _fail(self, msg: str, t0: float) -> AnalysisResult:
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message=msg,
            elapsed_seconds=time.perf_counter() - t0,
            metadata={"candidates": 0},
        )


class LimitedExhaustiveBruteForceAttack:
    """Последовательный перебор 64-битных ключей с лимитом (учебно)."""

    id = "brute_limited"
    title = "Ограниченный полный перебор"

    def __init__(self, deps: CryptoAnalysisDependencies, max_keys: int = 200_000) -> None:
        self._deps = deps
        self._max_keys = max(1, int(max_keys))

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if not ctx.plaintext_blocks or not ctx.ciphertext_blocks:
            return self._fail("Нужны блоки P и C.", t0)
        p, c = ctx.plaintext_blocks[0], ctx.ciphertext_blocks[0]
        eng = self._deps.engine
        sch = self._deps.schedule

        for i in range(self._max_keys):
            key = _key_from_index(i)
            rk = sch.expand(key, ctx.num_rounds)
            if eng.encrypt_block(p, rk, ctx.num_rounds) == c:
                elapsed = time.perf_counter() - t0
                return AnalysisResult(
                    attack_id=self.id,
                    title=self.title,
                    success=True,
                    message=f"Ключ найден за {i + 1} попыток (лимит {self._max_keys}).",
                    recovered_key_hex=bytes(key).hex(),
                    elapsed_seconds=elapsed,
                    details=f"index={i}",
                    metadata={"candidates": i + 1, "max_keys": self._max_keys},
                )
        elapsed = time.perf_counter() - t0
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message=f"За {self._max_keys} попыток ключ не найден. Пространство ключей 2^64.",
            elapsed_seconds=elapsed,
            details="Увеличьте лимит или используйте слабый класс ключей / другие атаки.",
            metadata={"candidates": self._max_keys, "max_keys": self._max_keys},
        )

    def _fail(self, msg: str, t0: float) -> AnalysisResult:
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message=msg,
            elapsed_seconds=time.perf_counter() - t0,
            metadata={"candidates": 0},
        )
