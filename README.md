<!-- astria-logo -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/astria-logo-reverse.svg">
    <img src=".github/assets/astria-logo.svg" alt="Astria" width="320">
  </picture>
</p>

# Astria api

BFF /api/v1 untuk web: sesi, peran, agregasi.

> Status: Tahap 1, BFF lengkap terhadap kontrak yang dirancang (42 operasi `/api/v1`, Command Facade `/svc/v1`, SSE). Layanan tujuan lain belum ada kodenya, jadi seluruh uji memakai tiruan upstream. Rancangan: `notes/2026-11-06-triase-dfir-app-api.md` dan `notes/2026-11-08-astria-api-implementasi.md` di repo root. Lajur developer: 3.

## Yang dilakukan

`api` tidak punya basis data dan satu proses. Ia menerjemahkan sesi cookie ke token layanan (dengan `act` pengguna), menegakkan peran, lalu meneruskan atau menggabungkan jawaban layanan lain.

| Permukaan | Pemanggil | Autentikasi |
|---|---|---|
| `/api/v1/*` | web (lewat Caddy) | cookie `astria_session` buram, introspeksi ke identity (cache 5 detik), cek Origin untuk metode tulis |
| `/api/v1/stream` | web | cookie yang sama; SSE hanya jenis, ID, dan status; difilter peran di server |
| `/svc/v1/*` | Gateway, Collector | HMAC per layanan (`X-Astria-Service/Ts/Nonce/Sig`, jendela 300 detik, nonce sekali pakai); tidak masuk OpenAPI publik |
| `/health`, `/ready`, `/metrics` | operator | tanpa autentikasi (lewat jaringan internal) |

## Otorisasi (RBAC)

Satu sumber kebenaran: [permissions.py](src/astria_api/permissions.py) (`GRANTS`: peran ke izin; `COMMAND_ROLES`: peran per perintah chat).

- Tolak secara bawaan. Peran tak dikenal atau kosong tidak mendapat apa pun.
- Rute menyebut izin (`authorize(Perm.CARDS_READ)`), bukan peran. Urutan: autentikasi, pembatas laju, otorisasi.
- Saat startup `assert_all_routes_protected` menolak jalan bila ada rute tanpa kebijakan (rute publik harus bertanda `@public`).
- Pemeriksaan objek: ikatan kanal hanya dapat dilihat atau dicabut pemiliknya (admin semua); milik orang lain dijawab 404.
- Perintah chat dicek ke identity per perintah tanpa cache, sehingga pencabutan peran langsung berlaku.
- `tests/routes/test_rbac.py` memuat matriks tulisan tangan (peran x rute) dan gagal bila kode menyimpang.

## Perilaku penting

- **Audit hibrida:** aksi berisiko dicatat ke audit **sebelum** dijalankan (gagal tertutup, 503 `AUDIT_TIDAK_TERSEDIA`) dan **sesudahnya** best-effort dengan antrean memori (`audit_tertunda` di `/health`).
- **Respons parsial:** kartu dan kanal menggabungkan layanan pelengkap; yang mati dilaporkan di `bagian_tidak_tersedia`, bukan galat.
- **Command Facade:** katalog tertutup T0/T1/T2; T2 mati bawaan (`chat.allow_t2`); T1 dan T2 butuh `confirmation_ref` dan `command_hash`; hasil dipangkas sesuai `max_detail` kanal.
- **Event:** langganan JetStream sendiri (skema event belum ada di `contracts`); `identity.revoked` menutup aliran SSE; `config.changed` membuang cache.

## Konfigurasi

Env `ASTRIA_*` (lihat [settings.py](src/astria_api/settings.py)). Di luar `test`: `ASTRIA_SERVICE_KEY` atau `_FILE` wajib; di `demo` dan `prod`: `ASTRIA_PUBLIC_ORIGIN` wajib. `ASTRIA_DATABASE_URL` ditolak. Kunci HMAC `/svc/v1`: berkas JSON `ASTRIA_SVC_KEYS_FILE` (`{"gateway":"<hex>","collector":"<hex>"}`); kosong berarti `/svc/v1` menolak semua.

## Tech stack

Python 3.14, FastAPI 0.162 (SSE bawaan), httpx, pydantic v2, orjson, hypothesis, uv.

## Perintah

```text
uv sync                                   # butuh akses ke repo privat contracts dan common (tag git)
uv run ruff format --check . && uv run ruff check .
uv run pytest
uv run python -m astria_api.snapshot      # perbarui openapi/api-v1.json setelah perubahan kontrak yang disengaja
sh ../common/template/localtest.sh        # di kontainer py devenv: uji terhadap salinan kerja common dan contracts
```

Kontrak `/api/v1` ada di [openapi/api-v1.json](openapi/api-v1.json); `tests/contract` gagal bila kode dan berkas berbeda.

Menjalankan bersama layanan lain: `pwsh ../devenv/scripts/dev.ps1 up`, lalu `dev.ps1 smoke`.

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
