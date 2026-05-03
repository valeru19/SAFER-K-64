"""Статистика байт шифротекста (энтропия, частоты)."""

from __future__ import annotations

import math
import time

from safer_k64.domain.models import AnalysisResult, AttackContext


class StatisticalAnalysis:
    id = "statistical"
    title = "Статистический анализ"

    def run(self, ctx: AttackContext) -> AnalysisResult:
        t0 = time.perf_counter()
        if not ctx.ciphertext_blocks:
            return AnalysisResult(
                attack_id=self.id,
                title=self.title,
                success=False,
                message="Нет блоков шифротекста.",
                elapsed_seconds=time.perf_counter() - t0,
            )
        counts = [0] * 256
        total = 0
        for block in ctx.ciphertext_blocks:
            for b in block:
                counts[b] += 1
                total += 1
        entropy = -sum((c / total) * math.log2(c / total) for c in counts if c > 0)
        top = sorted(enumerate(counts), key=lambda x: -x[1])[:5]
        lines = [f"Энтропия байт: {entropy:.4f} / 8.0", "Топ-5 байт по частоте:"]
        for byte, c in top:
            lines.append(f"  {byte:3d}: {c / total:.4%}")
        elapsed = time.perf_counter() - t0
        return AnalysisResult(
            attack_id=self.id,
            title=self.title,
            success=True,
            message="Статистика рассчитана (восстановление ключа не выполняется).",
            elapsed_seconds=elapsed,
            details="\n".join(lines),
            metadata={
                "entropy": entropy,
                "candidates": sum(1 for c in counts if c > 0),
            },
        )
