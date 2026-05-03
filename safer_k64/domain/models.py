from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

Block8 = list[int]
KeyHex = str


@dataclass(frozen=True)
class AttackContext:
    """Входные данные для атак (иммутабельный контекст)."""

    num_rounds: int
    plaintext_blocks: list[Block8]
    ciphertext_blocks: list[Block8]
    plain_pairs: Optional[list[tuple[Block8, Block8]]] = None
    cipher_pairs: Optional[list[tuple[Block8, Block8]]] = None
    known_key_bytes: Optional[list[int]] = None


@dataclass
class AnalysisResult:
    """Результат криптоанализа (единый формат для UI и логов)."""

    attack_id: str
    title: str
    success: bool
    message: str
    recovered_key_hex: Optional[str] = None
    elapsed_seconds: float = 0.0
    details: str = ""
    metadata: dict = field(default_factory=dict)
