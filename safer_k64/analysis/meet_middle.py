"""Учебная «встреча посередине» (упрощённая модель ключей)."""

from __future__ import annotations

import time
from collections import Counter

from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.domain.models import AnalysisResult, AttackContext


class MeetInTheMiddleAttack:
    id = "meet_middle"
    title = "Встреча посередине (демо)"

    def __init__(self, deps: CryptoAnalysisDependencies) -> None:
        self._deps = deps

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if ctx.num_rounds < 2 or ctx.num_rounds > 4:
            return self._fail("Поддерживаются 2–4 раунда.", t0)
        if not ctx.plaintext_blocks or not ctx.ciphertext_blocks:
            return self._fail("Нужны пары блоков P и C.", t0)

        eng = self._deps.engine
        sch = self._deps.schedule
        half = ctx.num_rounds // 2
        stats: Counter[tuple[int, ...]] = Counter()

        for p, c in zip(ctx.plaintext_blocks[:5], ctx.ciphertext_blocks[:5]):
            forward: dict[tuple[int, ...], list[int]] = {}
            for k1 in range(128):
                k1_vec = [k1] * 8
                rk1 = sch.expand(tuple(k1_vec), half)
                mid = tuple(eng.encrypt_block(p, rk1, half))
                forward[mid] = k1_vec
            for k2 in range(128):
                k2_vec = [k2] * 8
                rk2 = sch.expand(tuple(k2_vec), ctx.num_rounds - half)
                mid = tuple(eng.decrypt_block(c, rk2, ctx.num_rounds - half))
                if mid in forward:
                    guess = tuple(forward[mid])
                    rk = sch.expand(guess, ctx.num_rounds)
                    if eng.encrypt_block(p, rk, ctx.num_rounds) == c:
                        stats[guess] += 1

        elapsed = time.perf_counter() - t0
        if not stats:
            return AnalysisResult(
                attack_id=self.id,
                title=self.title,
                success=False,
                message="Ключ не найден (модель сильно упрощена).",
                elapsed_seconds=elapsed,
                metadata={"candidates": 0},
            )
        best_key, count = stats.most_common(1)[0]
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=True,
            message="Найден кандидат в учебной модели.",
            recovered_key_hex=bytes(best_key).hex(),
            elapsed_seconds=elapsed,
            details=f"Совпадений: {count}",
            metadata={"candidates": len(stats)},
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
