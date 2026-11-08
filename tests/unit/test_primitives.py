"""Cache TTL, pembatas laju, dan pemangkasan: uji contoh dan uji properti."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from astria_api import sanitize
from astria_api.cache import TTLCache
from astria_api.ratelimit import TokenBucket


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_cache_expires_and_drops() -> None:
    clock = Clock()
    cache: TTLCache[str, int] = TTLCache(5, clock=clock)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    assert cache.drop_where(lambda v: v == 2) == 1
    clock.now += 5
    assert cache.get("a") is None
    assert len(cache) == 0


def test_cache_is_bounded() -> None:
    cache: TTLCache[int, int] = TTLCache(60, max_size=3)
    for i in range(10):
        cache.set(i, i)
    assert len(cache) <= 3
    assert cache.get(9) == 9


def test_bucket_blocks_then_refills() -> None:
    clock = Clock()
    bucket = TokenBucket(2, 60, clock=clock)
    assert bucket.take("k") == 0
    assert bucket.take("k") == 0
    wait = bucket.take("k")
    assert 29 < wait <= 30
    clock.now += 30
    assert bucket.take("k") == 0
    assert bucket.take("other") == 0  # kunci lain tidak terpengaruh


@given(
    capacity=st.integers(min_value=1, max_value=50),
    gaps=st.lists(st.floats(min_value=0, max_value=5, allow_nan=False), min_size=1, max_size=300),
)
def test_bucket_never_allows_more_than_capacity_plus_refill(capacity: int, gaps: list[float]) -> None:
    clock = Clock()
    bucket = TokenBucket(capacity, 60, clock=clock)
    allowed = 0
    for gap in gaps:
        clock.now += gap
        if bucket.take("k") == 0:
            allowed += 1
    elapsed = sum(gaps)
    assert allowed <= capacity + elapsed * capacity / 60 + 1e-6


def test_bucket_bounded_keys() -> None:
    bucket = TokenBucket(1, 60, max_keys=5)
    for i in range(50):
        bucket.take(f"k{i}")
    assert len(bucket._buckets) <= 5


@given(
    st.dictionaries(st.text(max_size=12), st.one_of(st.integers(), st.text(max_size=20)), max_size=15),
    st.text(max_size=10),
)
def test_trim_never_adds_or_leaks_fields(result: dict, level: str) -> None:
    trimmed = sanitize.trim(result, level)
    allowed = sanitize.ALLOWED[sanitize.effective_level(level)]
    assert set(trimmed) <= set(allowed)
    assert set(trimmed) <= set(result)
    assert all(trimmed[k] == result[k] for k in trimmed)


def test_trim_levels_and_penuh_is_capped() -> None:
    card = {"card_id": "IC-1", "band": "KRITIS", "skor": 71, "narasi": "x", "secret": "y", "isi_log": "z"}
    assert set(sanitize.trim(card, "minimal")) == {"card_id", "band", "skor"}
    assert set(sanitize.trim(card, "ringkas")) == {"card_id", "band", "skor", "narasi"}
    assert sanitize.trim(card, "penuh") == sanitize.trim(card, "ringkas")
    assert sanitize.trim(card, "tidak_dikenal") == sanitize.trim(card, "minimal")


def test_mask_title() -> None:
    masked = sanitize.mask_title("Login mencurigakan di WS-ADM-04 dari 10.1.2.3")
    assert "10.1.2.3" not in masked
    assert "WS-ADM-04" not in masked
