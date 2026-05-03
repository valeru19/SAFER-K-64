"""Интерфейсы атак (ISP + DIP: узкий протокол, реализации отделены)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from safer_k64.domain.models import AnalysisResult, AttackContext


@runtime_checkable
class KeyRecoveryAttack(Protocol):
    id: str
    title: str

    def run(self, ctx: AttackContext) -> AnalysisResult: ...
