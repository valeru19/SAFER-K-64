"""Генерация примеров открытого текста."""

from __future__ import annotations

import random


class SampleTextService:
    _SAMPLES = (
        "Съешь ещё этих мягких французских булок, да выпей чаю.",
        "Hello, SAFER K-64 — учебный блок 8 байт, UTF-8.",
        "The quick brown fox jumps over the lazy dog. 1234567890",
        "Криптография: конфиденциальность, целостность, аутентичность.",
    )

    def random_sample(self) -> str:
        return random.choice(self._SAMPLES)

    def short_block_ascii(self) -> str:
        """Ровно 8 байт в ASCII для одного блока без паддинга (после UTF-8)."""
        return "ABCDEFGH"
