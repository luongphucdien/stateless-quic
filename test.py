import asyncio
import subprocess
import sys
import threading
import time
from pathlib import Path

from client import StatelessQUICClient

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 60000
ROOT_PATH = Path(__file__).parent
SERVER_STARTUP_TIMEOUT = 10

TEST_CASES: list[str] = [
    "Test",
    "Test longer string",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    + "Sed mauris enim, mollis eu sem at, blandit malesuada ex.",
]


def _forward_output(
    pipe, ready_event: threading.Event, prefix: str = "<SERVER>"
) -> None:
    try:
        for line in pipe:
            print(f"{prefix} {line}", end="", flush=True)

            if "::READY::" in line:
                ready_event.set()
    except Exception:
        pass


def start_server(startup_timeout: float = SERVER_STARTUP_TIMEOUT) -> subprocess.Popen:
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

    server_process = subprocess.Popen(
        [sys.executable, "-u", "server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=ROOT_PATH,
        creationflags=creation_flags,
    )

    ready_event = threading.Event()
    threading.Thread(
        target=_forward_output, args=(server_process.stdout, ready_event), daemon=True
    ).start()

    startup_deadline = time.monotonic() + startup_timeout
    while time.monotonic() < startup_deadline:
        if server_process.poll() is not None:
            raise RuntimeError(
                f"<ERR:SERVER> Server process exited early (code {server_process.returncode})"
            )

        if ready_event.wait(timeout=0.1):
            return server_process

    stop_server(server_process)
    raise RuntimeError(f"<ERR:SERVER> Server did not start within {startup_timeout}s")


def stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return

    print("<SERVER> Shutting down...")
    proc.terminate()

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print("<SERVER> Server is unresponsive, killing...")
        proc.kill()
        proc.wait()
    print(f"<SERVER> Server has stopped (exit code: {proc.returncode}).")


async def run_tests() -> tuple[int, int]:
    client = StatelessQUICClient(SERVER_HOST, SERVER_PORT)
    await client.connect()

    test_success = "<TEST:SUCCESS>"
    test_failed = "<TEST:FAILED>"
    passed = 0
    for msg in TEST_CASES:
        try:
            response: bytes = await client.call(msg)
            decoded = response.decode("utf-8", errors="replace")
            print(f"{test_success:<7} req : {msg!r}")
            print(f"{test_success:<7} res : {decoded!r}")
            passed += 1
        except Exception as exc:
            print(f"{test_failed:<7} req : {msg!r}")
            print(f"{test_failed:<7} exc : {exc}")

    if client.transport is not None:
        client.transport.close()

    return passed, len(TEST_CASES)


SEP = "=" * 64
SUB_SEP = "-" * 64


def main() -> None:
    server_proc: subprocess.Popen | None = None
    exit_code = 0

    try:
        print(SEP)
        print("<TEST_RUNNER> Starting server in the background...")
        server_proc = start_server()
        print("<TEST_RUNNER> Server is ready. Starting client tests...")
        print(SUB_SEP)

        passed, total = asyncio.run(run_tests())

        print(SUB_SEP)
        status = "PASSED" if passed == total else "FAILED"
        print(f"<TEST_RUNNER> {status} — {passed}/{total} tests passed.")
        exit_code = 0 if passed == total else 1

    except KeyboardInterrupt:
        print("<TEST_RUNNER> Interrupted by user.")
        exit_code = 130
    except Exception as exc:
        print(f"<TEST_RUNNER:ERR> FATAL: {exc}")
        exit_code = 2
    finally:
        if server_proc is not None:
            stop_server(server_proc)
        print(SEP)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
