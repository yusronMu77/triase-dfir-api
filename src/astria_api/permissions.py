"""Matriks izin berbasis peran (RBAC): satu-satunya sumber kebenaran otorisasi di api.

Aturan:

- **Tolak secara bawaan.** Peran tak dikenal, daftar peran kosong, dan izin yang tidak diberikan = ditolak.
- Rute tidak menyebut peran; ia menyebut **izin** (`authorize(Perm.CARDS_READ)`). Peran hanya dipetakan ke izin
  di `GRANTS`. Menambah peran atau mengubah akses cukup mengubah tabel ini.
- Penegakan di server (lapis kedua); menu yang tersembunyi di UI hanya kenyamanan.
- Perintah chat memakai pemetaan peran sendiri (`COMMAND_ROLES`) karena peran dicek ke identity per perintah.
- Pemeriksaan objek (kepemilikan) ada di `can_manage_identity`; izin saja tidak cukup untuk `identities:own`.

Sumber matriks: note api bagian 3.1 dan 3.3, note identity bagian 7.3, arsitektur aplikasi bagian 7.1.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum


class Role(StrEnum):
    ANALIS = "analis"
    DFIR = "dfir"
    PIMPINAN = "pimpinan"
    ADMIN = "admin"


class Perm(StrEnum):
    SESSION = "session"  # kelola sesi sendiri (me, logout, reauth); semua peran
    STREAM_READ = "stream:read"
    INGEST_READ = "ingest:read"
    INGEST_WRITE = "ingest:write"
    CARDS_READ = "cards:read"
    CARDS_WRITE = "cards:write"
    CARDS_DEEP_DIVE = "cards:deep_dive"
    CASES_READ = "cases:read"
    DIGESTS_READ = "digests:read"
    DIGESTS_RUN = "digests:run"
    HANDOVER = "handover"
    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    METRICS_READ = "metrics:read"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    SECRETS_WRITE = "secrets:write"
    CHANNELS_ADMIN = "channels:admin"
    IDENTITIES_ADMIN = "identities:admin"
    IDENTITIES_OWN = "identities:own"
    DEVICE_SCANS = "device_scans"


_ALL = frozenset(Perm)
_EVERY_ROLE = frozenset({Perm.SESSION, Perm.STREAM_READ, Perm.DIGESTS_READ, Perm.IDENTITIES_OWN})

GRANTS: dict[Role, frozenset[Perm]] = {
    # Pimpinan: hanya baca digest (dan kelola sesi serta ikatan kanal miliknya).
    Role.PIMPINAN: _EVERY_ROLE,
    Role.ANALIS: _EVERY_ROLE
    | {
        Perm.INGEST_READ,
        Perm.INGEST_WRITE,
        Perm.CARDS_READ,
        Perm.CARDS_WRITE,
        Perm.CARDS_DEEP_DIVE,
        Perm.HANDOVER,
        Perm.METRICS_READ,
        Perm.DEVICE_SCANS,
    },
    # Dfir: kasus dan baca audit; tanpa verifikasi audit, unggah ingest, serah terima, metrik, dan pindai perangkat.
    Role.DFIR: _EVERY_ROLE
    | {
        Perm.CARDS_READ,
        Perm.CARDS_WRITE,
        Perm.CARDS_DEEP_DIVE,
        Perm.CASES_READ,
        Perm.AUDIT_READ,
    },
    # Admin: konfigurasi, kanal, audit, metrik, ingest; sengaja tanpa antrean kartu, kasus, dan serah terima.
    Role.ADMIN: _EVERY_ROLE
    | {
        Perm.INGEST_READ,
        Perm.INGEST_WRITE,
        Perm.DIGESTS_RUN,
        Perm.AUDIT_READ,
        Perm.AUDIT_VERIFY,
        Perm.METRICS_READ,
        Perm.CONFIG_READ,
        Perm.CONFIG_WRITE,
        Perm.SECRETS_WRITE,
        Perm.CHANNELS_ADMIN,
        Perm.IDENTITIES_ADMIN,
        Perm.DEVICE_SCANS,
    },
}

# Jenis event SSE -> izin yang dibutuhkan untuk menerimanya (pemfilteran di server).
EVENT_PERMS: dict[str, Perm] = {
    "ticket.updated": Perm.CARDS_READ,
    "ticket.sla_breached": Perm.CARDS_READ,
    "job.progress": Perm.INGEST_READ,
    "digest.published": Perm.DIGESTS_READ,
}

# Katalog perintah chat (Command Facade): perintah -> (tingkat, peran yang boleh).
ALL_BOUND = frozenset(Role)
COMMAND_ROLES: dict[str, tuple[str, frozenset[Role]]] = {
    "status": ("T0", ALL_BOUND),
    # Admin menautkan bot dan menerima notifikasi kartu, jadi boleh membaca ringkasannya lewat chat (T0, baca saja).
    "queue": ("T0", frozenset({Role.ANALIS, Role.DFIR, Role.ADMIN})),
    "card": ("T0", frozenset({Role.ANALIS, Role.DFIR, Role.ADMIN})),
    "evidence_meta": ("T0", frozenset({Role.ANALIS, Role.DFIR, Role.ADMIN})),
    "digest_latest": ("T0", ALL_BOUND),
    "handover": ("T0", frozenset({Role.ANALIS})),
    "feedback": ("T1", frozenset({Role.ANALIS, Role.DFIR})),
    "deep_dive": ("T1", frozenset({Role.ANALIS, Role.DFIR})),
    "digest_run": ("T2", frozenset({Role.ADMIN})),
}


def role_set(roles: Iterable[str]) -> frozenset[Role]:
    """Hanya peran yang dikenal; nilai lain dibuang (tolak bawaan)."""
    known: set[Role] = set()
    for value in roles:
        try:
            known.add(Role(value))
        except ValueError:
            continue
    return frozenset(known)


def permissions_of(roles: Iterable[str]) -> frozenset[Perm]:
    granted: set[Perm] = set()
    for role in role_set(roles):
        granted |= GRANTS[role]
    return frozenset(granted)


def allows(roles: Iterable[str], perm: Perm) -> bool:
    return perm in permissions_of(roles)


def command_allowed(roles: Iterable[str], command: str) -> bool:
    spec = COMMAND_ROLES.get(command)
    return spec is not None and bool(spec[1] & role_set(roles))


def can_manage_identity(roles: Iterable[str], *, caller_user_id: str, owner_user_id: str | None) -> bool:
    """Admin boleh semua ikatan kanal; peran lain hanya ikatan miliknya. Pemilik tak diketahui = ditolak."""
    perms = permissions_of(roles)
    if Perm.IDENTITIES_ADMIN in perms:
        return True
    return Perm.IDENTITIES_OWN in perms and owner_user_id is not None and owner_user_id == caller_user_id
