"""Зависимости криптоанализа (внедрение движка и расписания)."""

from __future__ import annotations

from dataclasses import dataclass

from safer_k64.cipher.engine import SaferK64Engine
from safer_k64.cipher.key_schedule import RoundKeySchedule


@dataclass
class CryptoAnalysisDependencies:
    engine: SaferK64Engine
    schedule: RoundKeySchedule
