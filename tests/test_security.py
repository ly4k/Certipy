import pytest

from certipy.lib.constants import CertificateRights
from certipy.lib.security import CertificateSecurity, create_sd, is_admin_sid

DOMAIN = "S-1-5-21-1111-2222-3333"


@pytest.mark.parametrize("rid", [498, 500, 502, 512, 516, 518, 519, 521])
def test_is_admin_sid_domain_rids(rid: int):
    assert is_admin_sid(f"{DOMAIN}-{rid}")


@pytest.mark.parametrize("sid", ["S-1-5-9", "S-1-5-32-544"])
def test_is_admin_sid_builtin(sid: str):
    assert is_admin_sid(sid)


@pytest.mark.parametrize(
    "sid", [f"{DOMAIN}-1104", f"{DOMAIN}-513", "S-1-5-11", "S-1-1-0", f"{DOMAIN}-5000"]
)
def test_is_admin_sid_rejects_non_admin(sid: str):
    assert not is_admin_sid(sid)


def test_create_sd_round_trips_through_parser():
    owner = f"{DOMAIN}-1104"
    parsed = CertificateSecurity(create_sd(owner).getData())

    assert parsed.owner == owner
    assert set(parsed.aces) == {owner, "S-1-5-11"}
    assert parsed.aces[owner]["rights"] == CertificateRights.GENERIC_ALL
    assert parsed.aces["S-1-5-11"]["rights"] == CertificateRights.GENERIC_READ
    assert not parsed.aces[owner]["inherited"]
