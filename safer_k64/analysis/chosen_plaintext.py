"""Выбранный открытый текст: дифференциал по двум выбранным блокам при известном ключе."""

from __future__ import annotations

import time

from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.analysis.support import pack_key_tuple
from safer_k64.domain.models import AnalysisResult, AttackContext


class ChosenPlaintextAttack:
    id = "chosen_plaintext"
    title = "Выбранный открытый текст (демо)"

    def __init__(self, deps: CryptoAnalysisDependencies) -> None:
        self._deps = deps

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if not ctx.known_key_bytes:
            return self._fail("Укажите ключ: шифруются блоки нулей и дельта в первом байте.", t0)
        if ctx.num_rounds < 1 or ctx.num_rounds > 4:
            return self._fail("Раунды 1–4.", t0)

        key = pack_key_tuple(ctx.known_key_bytes)
        eng = self._deps.engine
        sch = self._deps.schedule
        rk = sch.expand(key, ctx.num_rounds)
        zero = [0] * 8
        delta = [1] + [0] * 7
        cz = eng.encrypt_block(zero, rk, ctx.num_rounds)
        cd = eng.encrypt_block(delta, rk, ctx.num_rounds)
        diff = [(a - b) % 256 for a, b in zip(cz, cd)]
        elapsed = time.perf_counter() - t0
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=True,
            message="Получена разность шифротекстов для пары открытых текстов.",
            elapsed_seconds=elapsed,
            details=f"ΔC = {diff}",
            metadata={"zero_cipher": cz, "delta_cipher": cd, "candidates": 2},
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
