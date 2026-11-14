"""Matriks RBAC: tolak secara bawaan, peran tak dikenal tidak pernah memberi izin, kepemilikan objek."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from astria_api.permissions import (
    COMMAND_ROLES,
    GRANTS,
    Perm,
    Role,
    allows,
    can_manage_identity,
    command_allowed,
    permissions_of,
)

# Tabel kebenaran ditulis ulang di sini (bukan diimpor) supaya perubahan GRANTS yang tidak disengaja gagal uji.
EXPECTED: dict[Perm, set[str]] = {
    Perm.SESSION: {"analis", "dfir", "pimpinan", "admin"},
    Perm.STREAM_READ: {"analis", "dfir", "pimpinan", "admin"},
    Perm.INGEST_READ: {"analis", "admin"},
    Perm.INGEST_WRITE: {"analis", "admin"},
    Perm.CARDS_READ: {"analis", "dfir"},
    Perm.CARDS_WRITE: {"analis", "dfir"},
    Perm.CARDS_DEEP_DIVE: {"analis", "dfir"},
    Perm.CASES_READ: {"dfir"},
    Perm.DIGESTS_READ: {"analis", "dfir", "pimpinan", "admin"},
    Perm.DIGESTS_RUN: {"admin"},
    Perm.HANDOVER: {"analis"},
    Perm.AUDIT_READ: {"dfir", "admin"},
    Perm.AUDIT_VERIFY: {"admin"},
    Perm.METRICS_READ: {"analis", "admin"},
    Perm.CONFIG_READ: {"admin"},
    Perm.CONFIG_WRITE: {"admin"},
    Perm.SECRETS_WRITE: {"admin"},
    Perm.CHANNELS_ADMIN: {"admin"},
    Perm.IDENTITIES_ADMIN: {"admin"},
    Perm.IDENTITIES_OWN: {"analis", "dfir", "pimpinan", "admin"},
    Perm.DEVICE_SCANS: {"analis", "admin"},
}


def test_every_permission_has_an_expected_row() -> None:
    assert set(EXPECTED) == set(Perm)


def test_grants_match_expected_matrix() -> None:
    for perm, roles in EXPECTED.items():
        granted = {r.value for r in Role if perm in GRANTS[r]}
        assert granted == roles, perm


def test_pimpinan_only_reads_digests() -> None:
    perms = permissions_of(["pimpinan"])
    assert Perm.DIGESTS_READ in perms
    assert not perms & {Perm.CARDS_READ, Perm.CARDS_WRITE, Perm.CONFIG_READ, Perm.AUDIT_READ, Perm.INGEST_WRITE}


def test_default_deny() -> None:
    assert permissions_of([]) == frozenset()
    assert permissions_of(["superuser", "ADMIN", "", "admin "]) == frozenset()
    assert not allows(["superuser"], Perm.SESSION)


@given(st.lists(st.text(max_size=20), max_size=6))
def test_unknown_roles_never_grant_anything(roles: list[str]) -> None:
    known = {r.value for r in Role}
    assert permissions_of(roles) == permissions_of([r for r in roles if r in known])


@given(st.lists(st.sampled_from([r.value for r in Role]), max_size=4))
def test_permissions_are_union_of_role_grants(roles: list[str]) -> None:
    expected: set[Perm] = set()
    for role in roles:
        expected |= GRANTS[Role(role)]
    assert permissions_of(roles) == expected


def test_only_admin_holds_secret_config_and_channel_permissions() -> None:
    for perm in (Perm.SECRETS_WRITE, Perm.CONFIG_WRITE, Perm.CHANNELS_ADMIN, Perm.DIGESTS_RUN, Perm.IDENTITIES_ADMIN):
        assert {r for r in Role if perm in GRANTS[r]} == {Role.ADMIN}


def test_command_catalog_roles() -> None:
    assert command_allowed(["analis"], "queue")
    assert not command_allowed(["pimpinan"], "queue")
    assert command_allowed(["pimpinan"], "digest_latest")
    assert not command_allowed(["analis"], "digest_run")
    assert command_allowed(["admin"], "digest_run")
    assert not command_allowed(["admin"], "feedback")
    assert not command_allowed(["analis"], "tidak_ada")
    assert not command_allowed([], "status")
    assert COMMAND_ROLES["digest_run"][0] == "T2"


def test_identity_ownership() -> None:
    assert can_manage_identity(["admin"], caller_user_id="usr_a", owner_user_id="usr_b")
    assert can_manage_identity(["analis"], caller_user_id="usr_a", owner_user_id="usr_a")
    assert not can_manage_identity(["analis"], caller_user_id="usr_a", owner_user_id="usr_b")
    assert not can_manage_identity(["analis"], caller_user_id="usr_a", owner_user_id=None)
    assert not can_manage_identity(["superuser"], caller_user_id="usr_a", owner_user_id="usr_a")
