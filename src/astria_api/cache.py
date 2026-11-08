"""Cache TTL kecil di memori proses (api stateless). Ukuran dibatasi agar tidak tumbuh tanpa batas."""

from __future__ import annotations

import time
from collections.abc import Callable, Hashable
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class TTLCache(Generic[K, V]):  # noqa: UP046 - sengaja eksplisit agar mudah dibaca
    def __init__(self, ttl: float, *, max_size: int = 10_000, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = ttl
        self._max = max_size
        self._clock = clock
        self._data: dict[K, tuple[float, V]] = {}

    def get(self, key: K) -> V | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if expires <= self._clock():
            del self._data[key]
            return None
        return value

    def set(self, key: K, value: V, ttl: float | None = None) -> None:
        if key not in self._data and len(self._data) >= self._max:
            self._evict()
        self._data[key] = (self._clock() + (self._ttl if ttl is None else ttl), value)

    def pop(self, key: K) -> V | None:
        item = self._data.pop(key, None)
        return item[1] if item else None

    def clear(self) -> None:
        self._data.clear()

    def drop_where(self, predicate: Callable[[V], bool]) -> int:
        doomed = [k for k, (_, v) in self._data.items() if predicate(v)]
        for key in doomed:
            del self._data[key]
        return len(doomed)

    def _evict(self) -> None:
        now = self._clock()
        for key in [k for k, (exp, _) in self._data.items() if exp <= now]:
            del self._data[key]
        while len(self._data) >= self._max:
            del self._data[next(iter(self._data))]

    def __len__(self) -> int:
        return len(self._data)
