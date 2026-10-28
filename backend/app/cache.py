import time


class ResponseCache:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: dict[str, tuple[float, dict]] = {}

    def get(self, key: str) -> dict | None:
        entry = self._entries.get(key)
        if entry is None:
            return None

        expires_at, value = entry
        if expires_at <= time.monotonic():
            del self._entries[key]
            return None
        return value

    def set(self, key: str, value: dict) -> None:
        self._entries[key] = (time.monotonic() + self.ttl_seconds, value)
