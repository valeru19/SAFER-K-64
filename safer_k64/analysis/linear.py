"""«Линейный» анализ: в основном перебор последнего байта с проверкой шифра."""

from __future__ import annotations

import time
from collections import Counter

from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.cipher.primitives import inverse_linear_transform, sub_key
from safer_k64.domain.models import AnalysisResult, AttackContext


class LinearCryptanalysisAttack:
    id = "linear"
    title = "Линейный криптоанализ (перебор с фильтром)"

    def __init__(self, deps: CryptoAnalysisDependencies) -> None:
        self._deps = deps

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if ctx.num_rounds > 4:
            return self._fail("Поддерживаются раунды 1–4.", t0)
        if not ctx.plaintext_blocks or not ctx.ciphertext_blocks:
            return self._fail("Нужны блоки открытого текста и шифротекста.", t0)
        if len(ctx.plaintext_blocks) != len(ctx.ciphertext_blocks):
            return self._fail("Число блоков P и C должно совпадать.", t0)

        eng = self._deps.engine
        sch = self._deps.schedule
        key_candidates: Counter[tuple[int, ...]] = Counter()

        for p, c in zip(ctx.plaintext_blocks, ctx.ciphertext_blocks):
            for k_last in range(256):
                k_last_vec = [k_last] * 8
                t = sub_key(c, k_last_vec)
                if ctx.num_rounds > 1:
                    t = inverse_linear_transform(t)
                rk = sch.expand(tuple(k_last_vec), ctx.num_rounds)
                if eng.encrypt_block(p, rk, ctx.num_rounds) == c:
                    key_candidates[tuple(k_last_vec)] += 1

        elapsed = time.perf_counter() - t0
        if not key_candidates:
            return AnalysisResult(
                attack_id=self.id,
                title=self.title,
                success=False,
                message="Ключ не найден.",
                elapsed_seconds=elapsed,
            )
        best_key, count = key_candidates.most_common(1)[0]
        hx = bytes(best_key).hex()
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=True,
            message="Найден кандидат ключа (проверка encrypt(P)=C).",
            recovered_key_hex=hx,
            elapsed_seconds=elapsed,
            details=f"Совпадений: {count}",
            metadata={"candidates": len(key_candidates)},
        )

    def _fail(self, msg: str, t0: float) -> AnalysisResult:
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message=msg,
            elapsed_seconds=time.perf_counter() - t0,
        )
