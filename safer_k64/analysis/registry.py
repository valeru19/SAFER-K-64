"""Реестр атак (OCP: новые атаки регистрируются без изменения ядра GUI)."""

from __future__ import annotations

from typing import Callable, Iterable

from safer_k64.analysis.brute_force import LimitedExhaustiveBruteForceAttack, UniformByteKeyBruteForceAttack
from safer_k64.analysis.chosen_plaintext import ChosenPlaintextAttack
from safer_k64.analysis.deps import CryptoAnalysisDependencies
from safer_k64.analysis.differential import DifferentialAttack
from safer_k64.analysis.integral import IntegralCryptanalysisAttack
from safer_k64.analysis.known_plaintext import KnownPlaintextAttack
from safer_k64.analysis.linear import LinearCryptanalysisAttack
from safer_k64.analysis.meet_middle import MeetInTheMiddleAttack
from safer_k64.analysis.protocols import KeyRecoveryAttack
from safer_k64.analysis.statistical import StatisticalAnalysis
from safer_k64.cipher.engine import SaferK64Engine
from safer_k64.cipher.key_schedule import RoundKeySchedule


class AttackRegistry:
    def __init__(self, attacks: Iterable[KeyRecoveryAttack]) -> None:
        self._attacks: list[KeyRecoveryAttack] = list(attacks)

    @property
    def attacks(self) -> tuple[KeyRecoveryAttack, ...]:
        return tuple(self._attacks)

    def by_id(self, attack_id: str) -> KeyRecoveryAttack | None:
        for a in self._attacks:
            if a.id == attack_id:
                return a
        return None


def default_registry(
    brute_max_keys: int = 200_000,
    deps_factory: Callable[[], CryptoAnalysisDependencies] | None = None,
) -> AttackRegistry:
    def _deps() -> CryptoAnalysisDependencies:
        return CryptoAnalysisDependencies(engine=SaferK64Engine(), schedule=RoundKeySchedule())

    factory = deps_factory or _deps
    d = factory()
    attacks: list[KeyRecoveryAttack] = [
        UniformByteKeyBruteForceAttack(d),
        LimitedExhaustiveBruteForceAttack(d, max_keys=brute_max_keys),
        KnownPlaintextAttack(d),
        LinearCryptanalysisAttack(d),
        DifferentialAttack(d),
        MeetInTheMiddleAttack(d),
        IntegralCryptanalysisAttack(d),
        ChosenPlaintextAttack(d),
        StatisticalAnalysis(),
    ]
    return AttackRegistry(attacks)
