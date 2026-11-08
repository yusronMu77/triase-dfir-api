"""Pemangkasan hasil untuk kanal chat menurut `max_detail` (note api bagian 5.5).

Daftar izin (allowlist) per tingkat: field di luar daftar dibuang. Tingkat `penuh` tidak berlaku untuk perintah
chat (dokumen penuh hanya lewat `/svc/v1/documents`), jadi dipangkas ke `ringkas`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MINIMAL = ("card_id", "band", "skor", "teknik", "host_samaran", "tautan")
RINGKAS = (*MINIMAL, "status", "prioritas", "narasi")

ALLOWED: dict[str, tuple[str, ...]] = {"minimal": MINIMAL, "ringkas": RINGKAS}
LEVELS = ("minimal", "ringkas", "penuh")

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOSTLIKE = re.compile(r"\b([A-Za-z]{2,})-[A-Za-z0-9-]*\d[A-Za-z0-9-]*\b")


def effective_level(level: str) -> str:
    """Tingkat yang dipakai perintah chat; tingkat tak dikenal jatuh ke yang paling ketat."""
    if level == "penuh":
        return "ringkas"
    return level if level in ALLOWED else "minimal"


def trim(result: Mapping[str, Any], level: str) -> dict[str, Any]:
    allowed = ALLOWED[effective_level(level)]
    return {key: result[key] for key in allowed if key in result}


def mask_title(title: str, *, max_len: int = 80) -> str:
    """Samarkan IP dan nama host pada judul untuk daftar antrean di chat."""
    masked = _IPV4.sub("x.x.x.x", title)
    masked = _HOSTLIKE.sub(lambda m: f"{m.group(1)}-***", masked)
    return masked[:max_len]
