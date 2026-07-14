import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Crypto:
    @staticmethod
    def generate_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
        private_key = x25519.X25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes_raw()
        return private_key, public_bytes

    @staticmethod
    def derive_secret(
        private_key: x25519.X25519PrivateKey, received_public_bytes: bytes
    ) -> bytes:
        received_public_key = x25519.X25519PublicKey.from_public_bytes(
            received_public_bytes
        )
        return private_key.exchange(received_public_key)

    @staticmethod
    def encrypt(payload: bytes, key: bytes) -> Tuple[bytes, bytes]:
        cipher = ChaCha20Poly1305(key[:32])
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, payload, None)
        return ciphertext, nonce

    @staticmethod
    def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
        cipher = ChaCha20Poly1305(key[:32])
        return cipher.decrypt(nonce, ciphertext, None)
