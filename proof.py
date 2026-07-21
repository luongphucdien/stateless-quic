"""
Tests that prove what provided in the proposal are true
1. Stateless design
2. FEC (Reed-Solomon) prevents retransmission
3. "Short-lived" (ephemeral)
4. X25519 + AEAD primitives
5. UDP, not TCP
"""

import asyncio
import unittest

from cryptography.exceptions import InvalidTag

from client import StatelessQUICClient
from core.codec import (
    HEADER_SIZE,
    NONCE_SIZE,
    PACKET_TYPE,
    PUBLIC_KEY_SIZE,
    pack_frame,
    unpack_frame,
)
from core.crypto import Crypto
from core.engine import StatelessQUIC
from core.reedsolomon import ReedSolomonEngine
from core.response_cache import ResponseCache


class TestStatelessDesign(unittest.TestCase):
    """
    Proves the stateless design.
    """

    def test_pack_unpack(self):
        """
        Test frame packing/unpacking.
        """
        frame = pack_frame(
            id=0xAAAAAAAA,
            packet_type=PACKET_TYPE.REQUEST,
            fec_block_id=42,
            proc_id=1,
            payload=b"Test Stateless Design",
        )

        header, payload = unpack_frame(frame)

        self.assertEqual(header.id, 0xAAAAAAAA)
        self.assertEqual(header.packet_type, PACKET_TYPE.REQUEST)
        self.assertEqual(header.fec_block_id, 42)
        self.assertEqual(header.proc_id, 1)
        self.assertEqual(payload, b"Test Stateless Design")

    def test_unordered_parse(self):
        """
        Test parsing unordered packets. Proves protocol does not rely on connection tracking.
        """
        frame_a = pack_frame(1, PACKET_TYPE.REQUEST, 1, 1, b"First")
        frame_b = pack_frame(2, PACKET_TYPE.RESPONSE, 2, 1, b"Second")
        frame_c = pack_frame(3, PACKET_TYPE.RETRY, 3, 2, b"Third")

        for frame, expected_id, expected_payload in [
            (frame_b, 2, b"Second"),
            (frame_a, 1, b"First"),
            (frame_c, 3, b"Third"),
        ]:
            header, payload = unpack_frame(frame)
            self.assertEqual(header.id, expected_id)
            self.assertEqual(payload, expected_payload)

    def test_truncated_frame(self):
        """
        Test incomplete frames will be rejected.
        """

        with self.assertRaises(ValueError):
            unpack_frame(b"\x00" * (HEADER_SIZE - 1))


class TestFECReedSolomon(unittest.TestCase):
    """
    Proves the no retransmission, self-recovering payload.
    """

    def test_reconstruction(self):
        """
        Test packet reconstruction.
        """

        engine = ReedSolomonEngine()
        payload = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed mauris enim, mollis eu sem at, blandit malesuada ex."
        encoded = bytearray(engine.encode(payload))

        encoded[4] ^= 0xFF
        encoded[2] ^= 0xFF

        recovered = engine.reconstruct_payload(bytes(encoded))

        self.assertEqual(recovered, payload)

    def test_out_of_capacity(self):
        """
        Test packet with heavy errors will be dropped. Reed-Solomon is just the primary mechanism.
        """

        engine = ReedSolomonEngine(ecc_symbols=2)
        payload = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed mauris enim, mollis eu sem at, blandit malesuada ex."
        encoded = bytearray(engine.encode(payload))

        encoded[4] ^= 0xFF
        encoded[2] ^= 0xFF

        recovered = engine.reconstruct_payload(bytes(encoded))

        self.assertIsNone(recovered)


class TestEphemeralState(unittest.TestCase):
    """
    Proves protocol does not rely on persistent connection. Instead, it relies on short-lived data.
    """

    def test_caching(self):
        """
        Test caching capability.
        """

        cache = ResponseCache()
        cache.put(request_id=42, response_frame=b"Response from cache")
        self.assertEqual(cache.get(42), b"Response from cache")

    def test_cache_expiry(self):
        """
        Test expired packets will be removed.
        """

        cache = ResponseCache(ttl=0)
        cache.put(request_id=42, response_frame=b"Should be expired")
        self.assertIsNone(cache.get(42))

    def test_caches_capacity(self):
        """
        Test cache eviction for older packets when capacity is reached.
        """

        cache = ResponseCache(ttl=60, max_entries=3)

        for i in range(5):
            cache.put(request_id=i, response_frame=f"Cache number {i}".encode())

        self.assertIsNone(cache.get(0))
        self.assertIsNone(cache.get(1))
        self.assertIsNotNone(cache.get(4))


class TestEncryption(unittest.TestCase):
    """
    Proves the usage of X25519 key exchange + AEAD encryption.
    """

    def test_key_exchange(self):
        """
        Test key exchange step.
        """

        alice_private, alice_public = Crypto.generate_keypair()
        bob_private, bob_public = Crypto.generate_keypair()

        alice_secret = Crypto.derive_secret(alice_private, bob_public)
        bob_secret = Crypto.derive_secret(bob_private, alice_public)

        self.assertEqual(alice_secret, bob_secret)

    def test_one_time_use_key(self):
        """
        Test generated keys for each session are unique.
        """

        _, public_a = Crypto.generate_keypair()
        _, public_b = Crypto.generate_keypair()

        self.assertNotEqual(public_a, public_b)

    def test_encrypt_decrypt(self):
        """
        Test AEAD encryption/decryption
        """

        private, public = Crypto.generate_keypair()
        peer_private, peer_public = Crypto.generate_keypair()

        secret = Crypto.derive_secret(private, peer_public)
        ciphertext, nonce = Crypto.encrypt(b"Test encryption", secret)

        peer_secret = Crypto.derive_secret(peer_private, public)
        plaintext = Crypto.decrypt(ciphertext, nonce, peer_secret)

        self.assertEqual(plaintext, b"Test encryption")

    def test_tamper_protection(self):
        """
        Test tampered payloads will be rejected with InvalidTag exception.
        """

        private, public = Crypto.generate_keypair()
        peer_private, peer_public = Crypto.generate_keypair()

        secret = Crypto.derive_secret(private, peer_public)
        ciphertext, nonce = Crypto.encrypt(b"Test integrity", secret)

        tampered_text = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        peer_secret = Crypto.derive_secret(peer_private, public)

        with self.assertRaises(InvalidTag):
            Crypto.decrypt(tampered_text, nonce, peer_secret)


class _RealLifeMimicProxy:
    def __init__(self, real_transport, on_send):
        self._real_transport = real_transport
        self._on_send = on_send

    def sendto(self, data, addr):
        action = self._on_send(data, addr)
        if action == "drop":
            return

        if isinstance(action, tuple) and action[0] == "corrupt":
            data = action[1]

        self._real_transport.sendto(data, addr)

    def __getattr__(self, name):
        return getattr(self._real_transport, name)


class TestRealLifeIntegration(unittest.IsolatedAsyncioTestCase):
    """
    Real-life-mocking integration.
    """

    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()

        self.calls = {"n": 0}

        async def counting_echo(payload: bytes) -> bytes:
            self.calls["n"] += 1
            return b"ECHO: " + payload

        server_transport, self.server_protocol = await loop.create_datagram_endpoint(
            lambda: StatelessQUIC(is_server=True), local_addr=("127.0.0.1", 0)
        )

        self.server_protocol.procedures = {1: counting_echo}
        self.server_transport = server_transport
        self.server_addr = server_transport.get_extra_info("sockname")

        self.client = StatelessQUICClient(
            *self.server_addr, self.server_protocol.public_key
        )
        await self.client.start()

    async def asyncTearDown(self):
        self.client.transport.close()
        self.server_transport.close()

    async def test_no_rtt(self):
        """
        Test connection between client-server with no-RTT, no handshaking. Client receives server response after sending only one packet.
        """

        sent = []
        self.client.transport = _RealLifeMimicProxy(
            self.client.transport,
            on_send=lambda data, addr: sent.append(data) or "send",
        )

        response = await self.client.call("First contact")

        self.assertEqual(response, b"ECHO: First contact")
        self.assertEqual(len(sent), 1)

    async def test_fec_recovery(self):
        """
        Test packet self-recovery after artificially corrupted.
        """

        sent = []

        def corrupt(data, addr):
            sent.append(data)

            if len(sent) == 1:
                data_as_array = bytearray(data)

                data_as_array[HEADER_SIZE + PUBLIC_KEY_SIZE + NONCE_SIZE] ^= 0xFF
                data_as_array[HEADER_SIZE + PUBLIC_KEY_SIZE + NONCE_SIZE + 1] ^= 0xFF

                return ("corrupt", bytes(data_as_array))

            return "send"

        self.client.transport = _RealLifeMimicProxy(
            self.client.transport, on_send=corrupt
        )

        response = await self.client.call("This should self-recover")

        self.assertEqual(response, b"ECHO: This should self-recover")
        self.assertEqual(len(sent), 1)

    async def test_hybrid_arq_fallback(self):
        """
        Test hybrid ARQ fallback in case the corrupted packets are too far gone.
        """

        sent = []

        def drop(data, addr):
            sent.append(data)
            return "drop" if len(sent) == 1 else "sent"

        self.client.transport = _RealLifeMimicProxy(self.client.transport, on_send=drop)

        response = await self.client.call("This should survive packet loss")

        self.assertEqual(response, b"ECHO: This should survive packet loss")
        self.assertGreaterEqual(len(sent), 2)

    async def test_retry_from_cache(self):
        """
        Test packet replaying from cache instead of forcing server to resend.
        """

        server_sent = []

        def drop(data, addr):
            server_sent.append(data)
            return "drop" if len(server_sent) == 1 else "send"

        self.server_protocol.transport = _RealLifeMimicProxy(
            self.server_protocol.transport, on_send=drop
        )

        response = await self.client.call("Idempotent retry")

        self.assertEqual(response, b"ECHO: Idempotent retry")
        self.assertEqual(self.calls["n"], 1)
        self.assertGreaterEqual(len(server_sent), 2)

    async def test_encryption(self):
        """
        Test packet encryption.
        """

        client_sent = []
        server_sent = []

        self.client.transport = _RealLifeMimicProxy(
            self.client.transport,
            on_send=lambda data, addr: client_sent.append(data) or "send",
        )
        self.server_protocol.transport = _RealLifeMimicProxy(
            self.server_protocol.transport,
            on_send=lambda data, addr: server_sent.append(data) or "send",
        )

        plaintext = "This should not be public"
        response = await self.client.call(plaintext)

        self.assertEqual(response, b"ECHO: " + plaintext.encode())

        plaintext_as_bytes = plaintext.encode()
        for frame in client_sent:
            self.assertNotIn(plaintext_as_bytes, frame)

        for frame in server_sent:
            self.assertNotIn(plaintext_as_bytes, frame)
            self.assertNotIn(b"ECHO: " + plaintext_as_bytes, frame)

    async def test_wrong_public_key(self):
        """
        Test malicious actor with forged public key will never reach the server
        """

        _, wrong_server_public = Crypto.generate_keypair()

        malicious_client = StatelessQUICClient(*self.server_addr, wrong_server_public)
        malicious_client.timeout = 0.05
        malicious_client.max_retries = 1
        await malicious_client.start()

        try:
            with self.assertRaises(ConnectionError):
                await malicious_client.call("This should never connect")
        finally:
            malicious_client.transport.close()

        self.assertEqual(self.calls["n"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
