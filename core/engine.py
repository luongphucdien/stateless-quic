import asyncio
import inspect
from typing import Callable, Dict, Tuple

from core.codec import PACKET_TYPE, Header, pack_frame, unpack_frame
from core.reedsolomon import ReedSolomonEngine


class StatelessQUIC(asyncio.DatagramProtocol):
    def __init__(self, is_server: bool = True):
        self.is_server = is_server
        self.transport = None
        self.fec_engine = ReedSolomonEngine()
        self.procedures: Dict[int, Callable[[bytes], bytes]] = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            header, encoded_payload = unpack_frame(data)

            decoded_payload = self.fec_engine.reconstruct_payload(encoded_payload)
            if decoded_payload is None:
                nack_frame = pack_frame(
                    header.id, PACKET_TYPE.NACK, header.fec_block_id, b"FEC Failed"
                )
                self.transport.sendto(nack_frame, addr)
                return

            if self.is_server:
                asyncio.create_task(self._process_rpc(header, decoded_payload, addr))
        except Exception:
            return

    async def _process_rpc(self, header: Header, payload: bytes, addr: Tuple[str, int]):
        handler = self.procedures.get(header.packet_type)
        if handler:
            response = (
                await handler(payload)
                if inspect.iscoroutinefunction(handler)
                else handler(payload)
            )

            encoded_response = self.fec_engine.encode(response)
            response_frame = pack_frame(
                header.id, 2, header.fec_block_id, encoded_response
            )
            self.transport.sendto(response_frame, addr)
