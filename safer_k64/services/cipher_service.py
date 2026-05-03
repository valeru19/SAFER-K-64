"""Прикладной сервис: шифрование/дешифрование сообщений и файлов."""

from __future__ import annotations

from pathlib import Path

from safer_k64.cipher.engine import SaferK64Engine
from safer_k64.cipher.key_schedule import RoundKeySchedule, validate_key_hex
from safer_k64.services.text_codec import blocks_to_utf8, utf8_to_blocks


class SaferK64ApplicationService:
    """Фасад над движком и расписанием ключей (SRP: сценарии приложения)."""

    def __init__(self, engine: SaferK64Engine | None = None, schedule: RoundKeySchedule | None = None) -> None:
        self._engine = engine or SaferK64Engine()
        self._schedule = schedule or RoundKeySchedule()

    def encrypt_text(self, plaintext: str, key_hex: str, num_rounds: int) -> bytes:
        key = validate_key_hex(key_hex)
        rk = self._schedule.expand(key, num_rounds)
        out = bytearray()
        for block in utf8_to_blocks(plaintext):
            out.extend(self._engine.encrypt_block(block, rk, num_rounds))
        return bytes(out)

    def decrypt_text(self, ciphertext: bytes, key_hex: str, num_rounds: int) -> str:
        if len(ciphertext) % 8 != 0:
            raise ValueError("Длина шифротекста должна быть кратна 8 байт")
        key = validate_key_hex(key_hex)
        rk = self._schedule.expand(key, num_rounds)
        blocks: list[list[int]] = []
        for i in range(0, len(ciphertext), 8):
            blocks.append(list(ciphertext[i : i + 8]))
        plain_blocks = [self._engine.decrypt_block(b, rk, num_rounds) for b in blocks]
        return blocks_to_utf8(plain_blocks)

    def encrypt_file(self, input_path: Path, output_path: Path, key_hex: str, num_rounds: int) -> None:
        data = Path(input_path).read_bytes()
        pad = 8 - (len(data) % 8)
        if pad == 0:
            pad = 8
        padded = data + bytes([pad] * pad)
        key = validate_key_hex(key_hex)
        rk = self._schedule.expand(key, num_rounds)
        out = bytearray()
        for i in range(0, len(padded), 8):
            block = list(padded[i : i + 8])
            out.extend(self._engine.encrypt_block(block, rk, num_rounds))
        Path(output_path).write_bytes(bytes(out))

    def decrypt_file(self, input_path: Path, output_path: Path, key_hex: str, num_rounds: int) -> None:
        data = Path(input_path).read_bytes()
        if len(data) % 8 != 0:
            raise ValueError("Длина файла не кратна 8")
        key = validate_key_hex(key_hex)
        rk = self._schedule.expand(key, num_rounds)
        blocks = [list(data[i : i + 8]) for i in range(0, len(data), 8)]
        plain = bytearray()
        for b in blocks:
            plain.extend(self._engine.decrypt_block(b, rk, num_rounds))
        pad_len = plain[-1]
        if 1 <= pad_len <= 8 and all(plain[-i] == pad_len for i in range(1, pad_len + 1)):
            plain = plain[:-pad_len]
        Path(output_path).write_bytes(bytes(plain))
