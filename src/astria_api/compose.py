"""Komposisi data dari beberapa layanan dengan respons parsial, plus cache konfigurasi.

Aturan (note api bagian 5.2): layanan pemilik data (`ticket`) gagal = galat berkode, tanpa data buatan;
layanan pelengkap (`config` untuk Penjelas) gagal = respons tetap dikirim dengan `bagian_tidak_tersedia`.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from typing import Any

from prometheus_client import Counter

from astria_api.cache import TTLCache
from astria_api.errors import ApiError, upstream_failed
from astria_api.upstream import Actor, Upstream, Upstreams

PARTIAL = Counter("astria_api_partial_responses_total", "Respons dengan bagian_tidak_tersedia", ["section"])

EVIDENCE_ID = re.compile(r"^EV-[A-Za-z0-9_-]{1,100}$")
MAX_EVIDENCE = 500
CATALOG_PENJELAS = "alert_penjelasan"


class ConfigCache:
    """Katalog aktif (60 dtk), pengaturan efektif (30 dtk), dan kebijakan kanal (30 dtk); panggilan sistem."""

    def __init__(self, config: Upstream, *, catalog_ttl: float, settings_ttl: float) -> None:
        self._config = config
        self._catalogs: TTLCache[str, dict[str, Any]] = TTLCache(catalog_ttl)
        self._settings: TTLCache[str, dict[str, Any]] = TTLCache(settings_ttl)
        self._policies: TTLCache[str, dict[str, Any]] = TTLCache(settings_ttl)

    async def catalog(self, kind: str) -> dict[str, Any]:
        cached = self._catalogs.get(kind)
        if cached is not None:
            return cached
        data = await self._config.json("GET", f"/svc/v1/catalogs/{kind}/active")
        if not isinstance(data, dict):
            raise upstream_failed("config")
        self._catalogs.set(kind, data)
        return data

    async def setting(self, scope: str, key: str) -> Any:
        values = self._settings.get(scope)
        if values is None:
            data = await self._config.json("GET", "/svc/v1/settings/effective", params={"scope": scope})
            if not isinstance(data, dict):
                raise upstream_failed("config")
            values = data.get("values", data)
            if not isinstance(values, dict):
                raise upstream_failed("config")
            self._settings.set(scope, values)
        return values.get(key)

    async def channel_policy(self, channel_id: str) -> dict[str, Any] | None:
        policy = self._policies.get(channel_id)
        if policy is not None:
            return policy
        data = await self._config.json("GET", "/svc/v1/channels/policy")
        items = data.get("items", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = [{"channel_id": k, **v} for k, v in items.items() if isinstance(v, dict)]
        if not isinstance(items, list):
            raise upstream_failed("config")
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("channel_id"), str):
                self._policies.set(item["channel_id"], item)
        return self._policies.get(channel_id)

    def invalidate(self, scope: str) -> None:
        if scope == "catalog":
            self._catalogs.clear()
        elif scope == "setting":
            self._settings.clear()
        elif scope == "channel_policy":
            self._policies.clear()
        else:
            for cache in (self._catalogs, self._settings, self._policies):
                cache.clear()


def penjelas_for(catalog: dict[str, Any], rule_ids: list[str]) -> dict[str, Any]:
    entries = catalog.get("entries")
    entries = entries if isinstance(entries, dict) else {}
    return {rid: entries[rid] for rid in rule_ids if isinstance(rid, str) and rid in entries}


def katalog_meta(catalog: dict[str, Any] | None) -> dict[str, Any] | None:
    if catalog is None:
        return None
    return {"versi": catalog.get("catalog_version"), "content_hash": catalog.get("content_hash")}


async def card_detail(upstreams: Upstreams, cache: ConfigCache, actor: Actor, card_id: str) -> dict[str, Any]:
    ticket, catalog = await asyncio.gather(
        upstreams.ticket.json("GET", f"/svc/v1/tickets/{card_id}", actor=actor),
        cache.catalog(CATALOG_PENJELAS),
        return_exceptions=True,
    )
    if isinstance(ticket, BaseException):
        raise ticket
    if not isinstance(ticket, dict):
        raise upstream_failed("ticket")
    missing: list[str] = []
    if isinstance(catalog, ApiError):
        missing.append("penjelas")
        PARTIAL.labels("penjelas").inc()
        catalog = None
    elif isinstance(catalog, BaseException):
        raise catalog
    rule_ids = ticket.get("rule_ids")
    if catalog and not rule_ids:
        # Ticket belum membawa RuleID (kode kartu triage belum memuatnya): turunkan dari alert pada bukti kartu.
        try:
            rule_ids = card_rule_ids(await evidence_items(upstreams, actor, evidence_ids(ticket)))
        except ApiError:
            missing.append("penjelas")
            PARTIAL.labels("penjelas").inc()
            catalog = None
    result = dict(ticket)
    if catalog and isinstance(rule_ids, list):
        result["rule_ids"] = rule_ids
    result["penjelas"] = penjelas_for(catalog, rule_ids) if catalog and isinstance(rule_ids, list) else None
    result["katalog"] = katalog_meta(catalog)
    result["bagian_tidak_tersedia"] = missing
    return result


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def evidence_ids(ticket: dict[str, Any]) -> list[str]:
    source = ticket.get("dokumen", ticket)
    return sorted({s for s in _strings(source) if EVIDENCE_ID.match(s)})[:MAX_EVIDENCE]


async def card_evidence(upstreams: Upstreams, actor: Actor, card_id: str) -> dict[str, Any]:
    ticket = await upstreams.ticket.json("GET", f"/svc/v1/tickets/{card_id}", actor=actor)
    if not isinstance(ticket, dict):
        raise upstream_failed("ticket")
    ids = evidence_ids(ticket)
    items = await evidence_items(upstreams, actor, ids)
    found = {i.get("evidence_id") for i in items if isinstance(i, dict)}
    return {"card_id": card_id, "evidence": items, "tidak_ditemukan": [i for i in ids if i not in found]}


async def evidence_items(upstreams: Upstreams, actor: Actor, ids: list[str]) -> list[Any]:
    if not ids:
        return []
    data = await upstreams.ingest.json("POST", "/svc/v1/evidence:batch", actor=actor, json={"ids": ids})
    # Kontrak ingest `EvidenceBatchResponse`: `items` dan `not_found`. Bentuk lain = hulu rusak, bukan "tidak ada".
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise upstream_failed("ingest")
    return items


def card_rule_ids(items: list[Any]) -> list[str]:
    """RuleID unik dari item bukti ingest, huruf kecil seperti kunci katalog `alert_penjelasan`."""
    return sorted({i["rule_id"].lower() for i in items if isinstance(i, dict) and isinstance(i.get("rule_id"), str)})


async def alert_explain(upstreams: Upstreams, cache: ConfigCache, actor: Actor, alert_id: str) -> dict[str, Any]:
    data = await upstreams.ingest.json("POST", "/svc/v1/alerts:batch", actor=actor, json={"ids": [alert_id]})
    alerts = data.get("alerts", []) if isinstance(data, dict) else []
    alert = next((a for a in alerts if isinstance(a, dict)), None) if isinstance(alerts, list) else None
    if alert is None:
        raise ApiError("TIDAK_DITEMUKAN", "data tidak ditemukan", 404)
    catalog = await cache.catalog(CATALOG_PENJELAS)
    rule_id = alert.get("rule_id")
    entries = penjelas_for(catalog, [rule_id] if isinstance(rule_id, str) else [])
    entry = entries.get(rule_id) if isinstance(rule_id, str) else None
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "penjelas": entry,
        "katalog": katalog_meta(catalog),
        "bagian_tidak_tersedia": [] if entry is not None else ["penjelas"],
    }
