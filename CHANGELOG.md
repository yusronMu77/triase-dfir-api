# Changelog

## [Unreleased]

### Added

- BFF `/api/v1` (42 operasi): sesi login/logout/reauth, antrean dan detail kartu (respons parsial), bukti, penjelas, ingest, kasus DFIR dan laporan, digest, serah terima, audit, metrik, konfigurasi dan rahasia, kanal, ikatan identitas, pindai perangkat; kontrak di `openapi/api-v1.json`.
- Otorisasi RBAC terpusat tolak-bawaan (`permissions.py`), pemeriksaan kepemilikan ikatan kanal, penjaga startup `assert_all_routes_protected`, uji matriks peran x rute.
- Command Facade `/svc/v1` dengan HMAC (nonce, jendela 300 detik), katalog tertutup T0/T1/T2, konfirmasi berikat hash, pemangkasan `max_detail`, pairing, dokumen, dan proksi Collector.
- SSE `/api/v1/stream` dengan pemfilteran peran di server, batas koneksi per pengguna, penutupan saat `identity.revoked`, dan sinyal `resync`.
- Audit hibrida: sebelum aksi gagal tertutup, sesudah aksi best-effort dengan antrean memori.
- Pembatas laju, cache TTL, pembersih kunci rahasia dari log, header keamanan, cek Origin (CSRF).
- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
