import asyncio
import os
import struct
from typing import Optional

from core.codec import PING_PROC_ID, pack_frame
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

    async def connect(
        self,
        max_attempts: int = 10,
        backoff_base: float = 0.3,
        backoff_max: float = 3.0,
    ) -> None:
        if self.transport is None:
            await self.start()

        last_exception: Optional[Exception] = None
        for attempt in range(1, max_attempts + 1):
            try:
                await self.call("", proc_id=PING_PROC_ID)
                return
            except (ConnectionError, asyncio.TimeoutError) as exception:
                last_exception = exception
                if attempt == max_attempts:
                    break
                delay = min(backoff_base * (2 ** (attempt - 1)), backoff_max)
                print(
                    f"<CLIENT_ERR> Server is not reachable. Retrying {attempt}/{max_attempts} in {delay:.1f}s..."
                )
                await asyncio.sleep(delay)

        raise ConnectionError(
            f"<CLIENT_ERR> Cannot reach server at {self.server_addr}"
        ) from last_exception

    async def call(self, message: str, proc_id: int = 1) -> bytes:
        request_id = struct.unpack(">Q", os.urandom(8))[0]

        raw_payload = message.encode("utf-8")
        encoded_payload = self.protocol.fec_engine.encode(raw_payload)

        future = asyncio.get_running_loop().create_future()
        self.protocol.pending_responses[request_id] = future

        attempt = 0
        packet_type = PACKET_TYPE.REQUEST

        while attempt <= self.max_retries:
            if attempt > 0:
                packet_type = PACKET_TYPE.RETRY
                print(
                    f"<CLIENT> No response received, packet may have been dropped. "
                    f"Retrying {attempt}/{self.max_retries}..."
                )

            packet = pack_frame(
                request_id,
                packet_type,
                fec_block_id=101,
                proc_id=proc_id,
                payload=encoded_payload,
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
                print(f"<CLIENT> NACK received (id={request_id:#x}): {e}")
                attempt += 1
                continue

        self.protocol.pending_responses.pop(request_id, None)
        raise ConnectionError("<CLIENT> Hybrid ARQ failed: Max retries exhausted.")
