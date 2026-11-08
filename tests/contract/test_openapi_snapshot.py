"""Snapshot OpenAPI `openapi/api-v1.json`: perubahan kontrak harus disengaja (`python -m astria_api.snapshot`)."""

from __future__ import annotations

import json

from astria_api.snapshot import SNAPSHOT, render


def test_snapshot_matches_generated_contract() -> None:
    assert SNAPSHOT.exists(), "jalankan: uv run python -m astria_api.snapshot"
    assert SNAPSHOT.read_text(encoding="utf-8") == render(), (
        "kontrak /api/v1 berubah; tinjau perubahan lalu jalankan: uv run python -m astria_api.snapshot"
    )


def test_contract_only_exposes_dashboard_api() -> None:
    schema = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert all(p.startswith("/api/v1/") for p in schema["paths"])
    assert not any(p.startswith(("/svc", "/internal", "/metrics", "/ready")) for p in schema["paths"])


def test_every_operation_documents_standard_errors_except_public_ones() -> None:
    schema = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    public = {"/api/v1/auth/login", "/api/v1/health"}
    for path, ops in schema["paths"].items():
        for method, op in ops.items():
            codes = set(op["responses"])
            if path in public:
                continue
            assert {"401", "403"} <= codes, (method, path)
