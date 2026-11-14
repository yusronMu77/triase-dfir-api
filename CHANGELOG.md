# Changelog

## [Unreleased]

### Changed

- Ringkasan operasi `POST /api/v1/cards/{card_id}/feedback` menjadi "Feedback analis" (sebelumnya "Umpan balik analis"); `openapi/api-v1.json` diperbarui. Hanya teks.

### Fixed

- api#12: impor alert dari web tidak pernah selesai. `POST /api/v1/ingest` kini memanggil ingest `POST /svc/v1/imports` (sebelumnya `/svc/v1/ingest/jobs` yang tidak ada) dan `GET /api/v1/ingest/jobs/{job_id}` membaca `GET /svc/v1/imports/{job_id}`, sesuai `contracts/openapi/ingest-internal.yaml`. Berkas yang sudah diimpor dijawab 200 dengan job lama (`created: false`). Kode tolak ingest yang dikenal (mis. `PATH_TIDAK_ADA`, `SHA256_TIDAK_COCOK`, `BERKAS_TERLALU_BESAR`) diteruskan sebagai 422 dengan pesan milik api; kode lain tetap 400 `VALIDASI_GAGAL`, detail server tidak diteruskan. `openapi/api-v1.json` diperbarui.
- `GET /api/v1/cards/{card_id}/evidence` menandai semua bukti "tidak ditemukan": api membaca kunci `evidence`, padahal ingest `POST /svc/v1/evidence:batch` membalas `items` dan `not_found`. Kini membaca `items`; bentuk lain dijawab 502 (hulu rusak), bukan daftar kosong.
- Bawaan `ASTRIA_GATEWAY_URL` menjadi `http://gateway:8080`: listener internal Gateway ada di 8080, sehingga probe kesehatan menandai gateway merah dan `/status` dari chat selalu "merah".

### Added

- `GET /api/v1/cases/{case_id}/custody` (izin `cases:read`): proksi ke dfir `/internal/v1/cases/{case_id}/custody`, rantai custody berhash beserta `chain_ok` yang dihitung dfir. `openapi/api-v1.json` diperbarui.
- Tautan bot WhatsApp untuk halaman Kanal (admin, `channels:admin`): `GET /api/v1/channels/whatsapp/link` (status, nomor tersamar, QR saat perlu pindai) dan `POST /api/v1/channels/whatsapp/link/logout` (putuskan tautan, audit sinkron `channel.whatsapp_unlink`), diteruskan ke gateway `/internal/v1/whatsapp/link`.
- BFF `/api/v1` (42 operasi): sesi login/logout/reauth, antrean dan detail kartu (respons parsial), bukti, penjelas, ingest, kasus DFIR dan laporan, digest, serah terima, audit, metrik, konfigurasi dan rahasia, kanal, ikatan identitas, pindai perangkat; kontrak di `openapi/api-v1.json`.
- Otorisasi RBAC terpusat tolak-bawaan (`permissions.py`), pemeriksaan kepemilikan ikatan kanal, penjaga startup `assert_all_routes_protected`, uji matriks peran x rute.
- Command Facade `/svc/v1` dengan HMAC (nonce, jendela 300 detik), katalog tertutup T0/T1/T2, konfirmasi berikat hash, pemangkasan `max_detail`, pairing, dokumen, dan proksi Collector.
- SSE `/api/v1/stream` dengan pemfilteran peran di server, batas koneksi per pengguna, penutupan saat `identity.revoked`, dan sinyal `resync`.
- Audit hibrida: sebelum aksi gagal tertutup, sesudah aksi best-effort dengan antrean memori.
- Pembatas laju, cache TTL, pembersih kunci rahasia dari log, header keamanan, cek Origin (CSRF).
- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
