"""Дифференциальный анализ (эвристика + проверка кандидатов)."""

from __future__ import annotations

import time
from collections import Counter

from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.analysis.support import build_differential_characteristic
from safer_k64.cipher.primitives import apply_sbox, inverse_linear_transform, sub_key
from safer_k64.cipher.tables import get_tables
from safer_k64.domain.models import AnalysisResult, AttackContext


class DifferentialAttack:
    id = "differential"
    title = "Дифференциальный анализ"

    def __init__(self, deps: CryptoAnalysisDependencies) -> None:
        self._deps = deps

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if ctx.num_rounds > 4:
            return self._fail("Поддерживаются раунды 1–4.", t0)
        pairs = ctx.plain_pairs
        cpairs = ctx.cipher_pairs
        if not pairs or not cpairs or len(pairs) != len(cpairs):
            return self._fail("Нужны пары (P1,P2) и (C1,C2) одинаковой длины.", t0)

        diff_in, diff_out, _pchar = build_differential_characteristic(ctx.num_rounds)
        log = get_tables().log_sbox
        eng = self._deps.engine
        sch = self._deps.schedule

        key_candidates: Counter[tuple[int, ...]] = Counter()
        for (p1, p2), (c1, c2) in zip(pairs, cpairs):
            input_diff = [(a - b) % 256 for a, b in zip(p1, p2)]
            if input_diff != diff_in:
                continue
            for k_last in range(256):
                k_last_vec = [k_last] * 8
                t1 = sub_key(c1, k_last_vec)
                t2 = sub_key(c2, k_last_vec)
                if ctx.num_rounds > 1:
                    t1 = inverse_linear_transform(t1)
                    t2 = inverse_linear_transform(t2)
                s1 = apply_sbox(t1, log)
                s2 = apply_sbox(t2, log)
                s_diff = [(a - b) % 256 for a, b in zip(s1, s2)]
                if s_diff != diff_out:
                    continue
                key_guess = tuple(k_last_vec)
                rk = sch.expand(key_guess, ctx.num_rounds)
                if eng.encrypt_block(p1, rk, ctx.num_rounds) == c1 and eng.encrypt_block(p2, rk, ctx.num_rounds) == c2:
                    key_candidates[key_guess] += 1

        elapsed = time.perf_counter() - t0
        if not key_candidates:
            return AnalysisResult(
                attack_id=self.id,
                title=self.title,
                success=False,
                message="Ключ не найден по выбранной характеристике.",
                elapsed_seconds=elapsed,
                details=f"Проверено пар: {len(pairs)}",
            )
        best_key, count = key_candidates.most_common(1)[0]
        rk = sch.expand(best_key, ctx.num_rounds)
        ok = eng.encrypt_block(pairs[0][0], rk, ctx.num_rounds) == cpairs[0][0] and eng.encrypt_block(
            pairs[0][1], rk, ctx.num_rounds
        ) == cpairs[0][1]
        hx = bytes(best_key).hex()
        if ok:
            return AnalysisResult(
                attack_id=self.id,
                title=self.title,
                success=True,
                message="Найден ключ, подтверждённый на первой паре.",
                recovered_key_hex=hx,
                elapsed_seconds=elapsed,
                details=f"Голосов: {count}",
                metadata={"candidates": len(key_candidates)},
            )
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message="Кандидат не подтвердился на проверочной паре.",
            recovered_key_hex=hx,
            elapsed_seconds=elapsed,
            details=str(dict(key_candidates.most_common(5))),
        )

    def _fail(self, msg: str, t0: float) -> AnalysisResult:
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message=msg,
            elapsed_seconds=time.perf_counter() - t0,
        )
