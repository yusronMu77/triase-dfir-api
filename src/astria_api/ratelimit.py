"""Pembatas laju token bucket per kunci, di memori proses (satu replika; lihat note api bagian 5.5)."""

from __future__ import annotations

import time
from collections.abc import Callable


class TokenBucket:
    """`capacity` token per `per_seconds`; isi ulang kontinu. `take` mengembalikan 0 bila diizinkan, selain itu
    jumlah detik sampai satu token tersedia."""

    def __init__(
        self,
        capacity: float,
        per_seconds: float = 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 50_000,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity harus positif")
        self.capacity = float(capacity)
        self._rate = capacity / per_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}

    def take(self, key: str) -> float:
        now = self._clock()
        tokens, last = self._buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self._rate)
        if tokens >= 1:
            self._store(key, tokens - 1, now)
            return 0.0
        self._store(key, tokens, now)
        return (1 - tokens) / self._rate

    def _store(self, key: str, tokens: float, now: float) -> None:
        if key not in self._buckets and len(self._buckets) >= self._max_keys:
            # Buang ember yang sudah penuh lagi (tidak ada yang hilang); bila tetap penuh, buang yang tertua.
            full = [
                k
                for k, (t, ts) in self._buckets.items()
                if min(self.capacity, t + (now - ts) * self._rate) >= self.capacity
            ]
            for k in full:
                del self._buckets[k]
            while len(self._buckets) >= self._max_keys:
                del self._buckets[next(iter(self._buckets))]
        self._buckets[key] = (tokens, now)
