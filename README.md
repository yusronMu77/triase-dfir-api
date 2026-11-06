# Astria api

BFF /api/v1 untuk web: sesi, peran, agregasi.

> Status: kerangka awal, belum ada kode. Repo ini adalah submodule dari workspace `triase-dfir` (folder `api/`). Rancangan: `notes/2026-11-06-triase-dfir-app-api.md` di repo root. Lajur developer: 3.

## Tech stack

Python 3.14, FastAPI, uv

## Perintah

```text
uv sync
uv run pytest
```

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
