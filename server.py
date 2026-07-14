import asyncio
from enum import IntEnum

from core.engine import StatelessQUIC


class PROC_ID(IntEnum):
    TEST = 1


async def test_procedure(payload: bytes) -> bytes:
    return b"REPLY: " + payload


async def main():
    loop = asyncio.get_running_loop()
    print("Starting server...")

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: StatelessQUIC(is_server=True), local_addr=("localhost", 60000)
    )

    protocol.procedures[1] = test_procedure

    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
