import pytest

from certipy.lib.constants import CertificateRights
from certipy.lib.structs import (
    AsReq,
    IntFlag,
    KDCOptions,
    PaPacRequest,
    PaPkAsReq,
    PrincipalName,
)


class Color(IntFlag):
    RED_ALERT = 1
    GREEN = 2
    BLUE = 4


def test_intflag_named_member_str_is_pascal_case():
    assert str(Color.RED_ALERT) == "RedAlert"


def test_intflag_combination_lists_members():
    combo = Color.RED_ALERT | Color.BLUE
    assert combo.to_list() == [Color.RED_ALERT, Color.BLUE]
    assert combo.to_str_list() == ["RedAlert", "Blue"]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Python 3.11+ gives combined IntFlag values a name like 'A|B', so "
        "__str__ never reaches its comma-join branch and returns 'RedAlert|Blue'"
    ),
)
def test_intflag_combination_str_is_comma_separated():
    assert str(Color.RED_ALERT | Color.BLUE) == "RedAlert, Blue"


def test_intflag_empty():
    assert Color(0).to_list() == []
    assert str(Color(0)) == ""


def test_intflag_repr_matches_str():
    assert repr(Color.GREEN) == "Green"


def test_certificate_rights_named_member_str():
    rights = CertificateRights.GENERIC_READ
    assert str(rights) == "GenericRead"


def test_pa_pac_request_round_trip():
    encoded = PaPacRequest({"include-pac": True}).dump()
    assert PaPacRequest.load(encoded)["include-pac"].native is True


def test_principal_name_round_trip():
    name = PrincipalName({"name-type": 2, "name-string": ["krbtgt", "CORP.LOCAL"]})
    decoded = PrincipalName.load(name.dump())
    assert decoded.native == {
        "name-type": 2,
        "name-string": ["krbtgt", "CORP.LOCAL"],
    }


def test_kdc_options_round_trip():
    options = KDCOptions({"forwardable", "renewable", "canonicalize"})
    assert KDCOptions.load(options.dump()).native == {
        "forwardable",
        "renewable",
        "canonicalize",
    }


def test_pa_pk_as_req_round_trip():
    request = PaPkAsReq({"signedAuthPack": b"\x30\x00"})
    assert PaPkAsReq.load(request.dump()).native == request.native


def test_as_req_round_trip():
    request = AsReq(
        {
            "pvno": 5,
            "msg-type": 10,
            "padata": [{"padata-type": 16, "padata-value": b"\x30\x00"}],
            "req-body": {
                "kdc-options": {"forwardable", "renewable", "canonicalize"},
                "cname": {"name-type": 1, "name-string": ["alice"]},
                "realm": "CORP.LOCAL",
                "sname": {"name-type": 2, "name-string": ["krbtgt", "CORP.LOCAL"]},
                "till": "20370913024805Z",
                "nonce": 12345,
                "etype": [18, 17, 23],
            },
        }
    )
    decoded = AsReq.load(request.dump())
    assert decoded.native == request.native
    assert decoded["req-body"]["realm"].native == "CORP.LOCAL"
