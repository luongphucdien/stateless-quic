import asyncio
from enum import IntEnum
from typing import Callable, Dict, Optional

from core.engine import StatelessQUIC


class StatelessQUICServer:
    def __init__(
        self,
        host: str,
        port: int,
        procedure_mapping: Dict[int, Callable[[bytes], bytes]] = {},
    ):
        self.server_addr = (host, port)
        self.procedure_mapping = procedure_mapping
        self.protocol = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: StatelessQUIC(is_server=True), local_addr=self.server_addr
        )

        self.protocol = protocol
        protocol.procedures = self.procedure_mapping

        print(
            f"Server is ready on {self.server_addr[0]}:{self.server_addr[1]}",
            flush=True,
        )

        try:
            await asyncio.Event().wait()
        finally:
            transport.close()


class PROC_ID(IntEnum):
    TEST = 1


async def test_procedure(payload: bytes) -> bytes:
    return b"REPLY: " + payload


procedure_mapping = {PROC_ID.TEST: test_procedure}


def main() -> None:
    HOST = "127.0.0.1"
    PORT = 60000
    server = StatelessQUICServer(HOST, PORT, procedure_mapping)
    asyncio.run(server.start())


if __name__ == "__main__":
    main()
