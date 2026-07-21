import asyncio
import inspect
from typing import Callable, Dict, Optional, Tuple

from core.codec import PACKET_TYPE, PING_PROC_ID, Header, pack_frame, unpack_frame
from core.reedsolomon import ReedSolomonEngine
from core.response_cache import ResponseCache


class StatelessQUIC(asyncio.DatagramProtocol):
    def __init__(self, is_server: bool = True):
        self.is_server = is_server
        self.transport = None
        self.fec_engine = ReedSolomonEngine()
        self.procedures: Dict[int, Callable[[bytes], bytes]] = {}

        self._response_cache: Optional[ResponseCache] = (
            ResponseCache() if is_server else None
        )
        self.pending_responses: Dict[int, asyncio.Future] = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            header, encoded_payload = unpack_frame(data)

            decoded_payload = self.fec_engine.reconstruct_payload(encoded_payload)
            if decoded_payload is None:
                nack_frame = pack_frame(
                    header.id,
                    PACKET_TYPE.NACK,
                    header.fec_block_id,
                    header.proc_id,
                    b"FEC Failed",
                )
                self.transport.sendto(nack_frame, addr)
                return

            if self.is_server:
                self._handle_server(header, decoded_payload, addr)
            else:
                self._handle_client(header, decoded_payload)

        except Exception:
            return

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
        if header.proc_id == PING_PROC_ID:
            response: bytes = b"PONG"
        else:
            handler = self.procedures.get(header.proc_id)
            if handler is None:
                print(f"<SERVER> No handler for process {header.proc_id}")
                return

            response: bytes = (
                await handler(payload)
                if inspect.iscoroutinefunction(handler)
                else handler(payload)
            )

        encoded_response = self.fec_engine.encode(response)
        response_frame = pack_frame(
            header.id,
            PACKET_TYPE.RESPONSE,
            header.fec_block_id,
            header.proc_id,
            encoded_response,
        )

        self._response_cache.put(header.id, response_frame)
        self.transport.sendto(response_frame, addr)

    def _handle_client(self, header: Header, payload: bytes):
        if header.packet_type == PACKET_TYPE.RESPONSE:
            future = self.pending_responses.pop(header.id, None)
            if future and not future.done():
                future.set_result(payload)

        elif header.packet_type == PACKET_TYPE.NACK:
            future = self.pending_responses.pop(header.id, None)
            if future and not future.done():
                error_msg = payload.decode(errors="replace")
                future.set_exception(RuntimeError(error_msg))
