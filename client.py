import asyncio
import os
import struct

from core.codec import pack_frame
from core.engine import PACKET_TYPE, StatelessQUIC


class StatelessQUICClient:
    def __init__(self, server_host: str, server_port: int):
        self.server_addr = (server_host, server_port)
        self.transport = None
        self.protocol = None
        self.max_retries = 5
        self.timeout = 0.2

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: StatelessQUIC(is_server=False), local_addr=("0.0.0.0", 0)
        )

    async def call(self, message: str) -> bytes:
        id = struct.unpack(">Q", os.urandom(8))[0]

        raw_payload = message.encode("utf-8")
        encoded_payload = self.protocol.fec_engine.encode(raw_payload)

        future = asyncio.get_running_loop().create_future()
        self.protocol.pending_responses[id] = future

        attempt = 0
        packet_type = PACKET_TYPE.REQUEST

        while attempt <= self.max_retries:
            if attempt > 0:
                packet_type = PACKET_TYPE.RETRY
                print(
                    f"<CLIENT> No packet received, must be dropped. Retrying {attempt}/{self.max_retries}..."
                )

            packet = pack_frame(
                id, packet_type, fec_block_id=101, payload=encoded_payload
            )
            self.transport.sendto(packet, self.server_addr)

            try:
                current_timeout = self.timeout * (2**attempt)
                return await asyncio.wait_for(
                    asyncio.shield(future), timeout=current_timeout
                )
            except asyncio.TimeoutError:
                attempt += 1
                continue
            except RuntimeError as e:
                print(f"<CLIENT> NACK received (ID: {id})")
                print(e)
                attempt += 1
                continue

        self.protocol.pending_responses.pop(id, None)
        raise ConnectionError("<CLIENT> Hybrid ARQ failed.")
