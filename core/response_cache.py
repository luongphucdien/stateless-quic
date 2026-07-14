import time
from collections import OrderedDict
from typing import Optional


class ResponseCache:
    def __init__(self, ttl: float = 5.0, max_entries: int = 1024) -> None:
        self._ttl = ttl
        self._max_entries = max_entries
        self._cache: OrderedDict[int, tuple[bytes, float]] = OrderedDict()

    def put(self, request_id: int, response_frame: bytes) -> None:
        self._remove_expired()

        if request_id in self._cache:
            self._cache.move_to_end(request_id)

        self._cache[request_id] = (response_frame, time.monotonic() + self._ttl)

        while len(self._cache) > self._max_entries:
            self._cache.popitem(last=False)

    def get(self, request_id: int) -> Optional[bytes]:
        self._remove_expired()

        entry = self._cache.get(request_id)
        if entry is None:
            return None

        response_frame, expiry = entry
        if time.monotonic() > expiry:
            del self._cache[request_id]
            return None

        self._cache.move_to_end(request_id)
        return response_frame

    def _remove_expired(self) -> None:
        now = time.monotonic()
        expired_entries = [k for k, (_, expiry) in self._cache.items() if expiry <= now]
        for k in expired_entries:
            del self._cache[k]
