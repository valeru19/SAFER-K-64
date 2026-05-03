"""Интегральный анализ: требуется известный ключ для построения интегральной структуры (оракул)."""

from __future__ import annotations

import time
from collections import Counter

from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.analysis.support import pack_key_tuple
from safer_k64.cipher.primitives import apply_sbox, inverse_linear_transform, sub_key
from safer_k64.cipher.tables import get_tables
from safer_k64.domain.models import AnalysisResult, AttackContext


class IntegralCryptanalysisAttack:
    id = "integral"
    title = "Интегральный анализ (с оракулом шифрования)"

    def __init__(self, deps: CryptoAnalysisDependencies) -> None:
        self._deps = deps

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if ctx.num_rounds > 4:
            return self._fail("Поддерживаются раунды 1–4.", t0)
        if not ctx.known_key_bytes:
            return self._fail("Укажите известный ключ: он нужен для генерации 256 интегральных шифротекстов.", t0)
        if not ctx.plaintext_blocks or not ctx.ciphertext_blocks:
            return self._fail("Нужны блоки P и C.", t0)

        real_key = pack_key_tuple(ctx.known_key_bytes)
        log = get_tables().log_sbox
        eng = self._deps.engine
        sch = self._deps.schedule

        base = ctx.plaintext_blocks[0][:]
        integral_plain = [[i] + base[1:] for i in range(256)]
        rk_real = sch.expand(real_key, ctx.num_rounds)
        integral_cipher = [eng.encrypt_block(p, rk_real, ctx.num_rounds) for p in integral_plain]

        key_candidates: Counter[tuple[int, ...]] = Counter()
        for k_last in range(256):
            k_last_vec = [k_last] * 8
            s0 = 0
            for ciph in integral_cipher:
                t = sub_key(ciph, k_last_vec)
                if ctx.num_rounds > 1:
                    t = inverse_linear_transform(t)
                t = apply_sbox(t, log)
                s0 = (s0 + t[0]) % 256
            if s0 != 0:
                continue
            guess = tuple(k_last_vec)
            rk = sch.expand(guess, ctx.num_rounds)
            if all(eng.encrypt_block(p, rk, ctx.num_rounds) == c for p, c in zip(ctx.plaintext_blocks[:2], ctx.ciphertext_blocks[:2])):
                key_candidates[guess] += 1

        elapsed = time.perf_counter() - t0
        if not key_candidates:
            return AnalysisResult(
                attack_id=self.id,
                title=self.title,
                success=False,
                message="Ключ не найден по интегральному критерию.",
                elapsed_seconds=elapsed,
            )
        best_key, count = key_candidates.most_common(1)[0]
        rk = sch.expand(best_key, ctx.num_rounds)
        ok = all(eng.encrypt_block(p, rk, ctx.num_rounds) == c for p, c in zip(ctx.plaintext_blocks, ctx.ciphertext_blocks))
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=bool(ok),
            message="Ключ подтверждён на всех блоках." if ok else "Кандидат не подтвердился на всех блоках.",
            recovered_key_hex=bytes(best_key).hex(),
            elapsed_seconds=elapsed,
            details=f"Голосов: {count}",
        )

    def _fail(self, msg: str, t0: float) -> AnalysisResult:
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=False,
            message=msg,
            elapsed_seconds=time.perf_counter() - t0,
        )
