from typing import Optional

from reedsolo import ReedSolomonError, RSCodec


class ReedSolomonEngine:
    def __init__(self, ecc_symbols: int = 4):
        self.codec = RSCodec(ecc_symbols)
        self.ecc_symbols = ecc_symbols

    def encode(self, payload: bytes) -> bytes:
        return self.codec.encode(payload)

    def reconstruct_payload(self, frame: bytes) -> Optional[bytes]:
        try:
            decoded_payload, _, _ = self.codec.decode(frame)
            return decoded_payload
        except ReedSolomonError:
            return None
