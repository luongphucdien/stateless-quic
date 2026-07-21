import asyncio
import inspect
from typing import Callable, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag

from core.codec import (
    NONCE_SIZE,
    PACKET_TYPE,
    PING_PROC_ID,
    PUBLIC_KEY_SIZE,
    Header,
    pack_frame,
    unpack_frame,
)
from core.crypto import Crypto
from core.reedsolomon import ReedSolomonEngine
from core.response_cache import ResponseCache


class StatelessQUIC(asyncio.DatagramProtocol):
    def __init__(self, is_server: bool = True, peer_public_key: Optional[bytes] = None):
        self.is_server = is_server
        self.transport = None
        self.fec_engine = ReedSolomonEngine()
        self.procedures: Dict[int, Callable[[bytes], bytes]] = {}

        self._response_cache: Optional[ResponseCache] = (
            ResponseCache() if is_server else None
        )
        self.pending_responses: Dict[int, asyncio.Future] = {}

        if is_server:
            self._server_private_key, self.public_key = Crypto.generate_keypair()
        else:
            if peer_public_key is None:
                raise ValueError("No server's public key available")

            self._client_private_key, self.public_key = Crypto.generate_keypair()
            self.shared_secret = Crypto.derive_secret(
                self._client_private_key, peer_public_key
            )

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            header, encoded_payload = unpack_frame(data)

            if header.packet_type == PACKET_TYPE.NACK:
                self._handle_nack(header, encoded_payload)
                return

            if self.is_server:
                self._handle_server(header, encoded_payload, addr)
            else:
                self._handle_client(header, encoded_payload)

        except Exception:
            return

    def _handle_nack(self, header: Header, payload: bytes):
        future = self.pending_responses.pop(header.id, None)
        if future and not future.done():
            future.set_exception(RuntimeError(payload.decode(errors="replace")))

    def _send_nack(self, header: Header, addr: Tuple[str, int], reason: bytes):
        nack_frame = pack_frame(
            header.id, PACKET_TYPE.NACK, header.fec_block_id, header.proc_id, reason
        )
        self.transport.sendto(nack_frame, addr)

    def _handle_server(self, header: Header, payload: bytes, addr: Tuple[str, int]):
        if header.packet_type == PACKET_TYPE.RETRY:
            cached_frame = self._response_cache.get(header.id)
            if cached_frame is not None:
                print(
                    f"<SERVER> Cached response hit for id={header.id:#x}. Replaying..."
                )
                self.transport.sendto(cached_frame, addr)
                return

            print(
                f"<SERVER> Cached response missed for id={header.id:#x}. Fresh request..."
            )

        asyncio.create_task(self._process_rpc(header, payload, addr))

    async def _process_rpc(self, header: Header, payload: bytes, addr: Tuple[str, int]):
        if len(payload) < PUBLIC_KEY_SIZE + NONCE_SIZE:
            self._send_nack(header, addr, b"Malformed payload")
            return

        client_public_key = payload[:PUBLIC_KEY_SIZE]
        nonce = payload[PUBLIC_KEY_SIZE : PUBLIC_KEY_SIZE + NONCE_SIZE]
        encoded_ciphertext = payload[PUBLIC_KEY_SIZE + NONCE_SIZE :]

        ciphertext = self.fec_engine.reconstruct_payload(encoded_ciphertext)
        if ciphertext is None:
            self._send_nack(header, addr, b"FEC failed")
            return

        shared_secret = Crypto.derive_secret(
            self._server_private_key, client_public_key
        )

        try:
            true_payload = Crypto.decrypt(ciphertext, nonce, shared_secret)
        except InvalidTag:
            self._send_nack(header, addr, b"Decryption failed")

        if header.proc_id == PING_PROC_ID:
            response: bytes = b"PONG"
        else:
            handler = self.procedures.get(header.proc_id)
            if handler is None:
                print(f"<SERVER> No handler for process {header.proc_id}")
                return

            response: bytes = (
                await handler(true_payload)
                if inspect.iscoroutinefunction(handler)
                else handler(true_payload)
            )

        response_ciphertext, response_nonce = Crypto.encrypt(response, shared_secret)
        encoded_response = self.fec_engine.encode(response_ciphertext)
        response_payload = response_nonce + encoded_response
        response_frame = pack_frame(
            header.id,
            PACKET_TYPE.RESPONSE,
            header.fec_block_id,
            header.proc_id,
            response_payload,
        )

        self._response_cache.put(header.id, response_frame)
        self.transport.sendto(response_frame, addr)

    def _handle_client(self, header: Header, payload: bytes):
        if header.packet_type != PACKET_TYPE.RESPONSE:
            return

        future = self.pending_responses.get(header.id)
        if future is None or future.done():
            return

        if len(payload) < NONCE_SIZE:
            return

        nonce = payload[:NONCE_SIZE]
        encoded_ciphertext = payload[NONCE_SIZE:]

        ciphertext = self.fec_engine.reconstruct_payload(encoded_ciphertext)
        if ciphertext is None:
            return

        try:
            true_payload = Crypto.decrypt(ciphertext, nonce, self.shared_secret)
        except InvalidTag:
            return

        self.pending_responses.pop(header.id, None)
        future.set_result(true_payload)
