import argparse
from typing import Any

import pytest

from certipy.lib import target as target_module
from certipy.lib.target import DnsResolver, Target, is_ip


@pytest.mark.parametrize("value", ["10.0.0.1", "192.168.56.10", "127.0.0.1"])
def test_is_ip_accepts_ipv4(value: str):
    assert is_ip(value)


@pytest.mark.parametrize("value", ["dc01.corp.local", "corp.local", "", None])
def test_is_ip_rejects_names_and_empty(value: Any):
    assert not is_ip(value)


@pytest.mark.xfail(
    strict=True, reason="is_ip uses socket.inet_aton, which rejects IPv6"
)
def test_is_ip_accepts_ipv6():
    assert is_ip("fe80::1")


class FakeResolver:
    def __init__(self) -> None:
        self.lookups: list[str] = []

    def resolve(self, hostname: str) -> str:
        self.lookups.append(hostname)
        return "10.0.0.99"


@pytest.fixture
def resolver(monkeypatch: pytest.MonkeyPatch) -> FakeResolver:
    fake = FakeResolver()
    monkeypatch.setattr(DnsResolver, "create", staticmethod(lambda **_: fake))
    return fake


def _options(**kw: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "username": "alice@corp.local",
        "password": "Passw0rd!",
        "dc_ip": "10.0.0.1",
    }
    defaults.update(kw)
    return argparse.Namespace(**defaults)


def test_from_options_splits_and_uppercases_principal(resolver: FakeResolver):
    target = Target.from_options(_options())
    assert (target.username, target.domain) == ("ALICE", "CORP.LOCAL")
    assert target.password == "Passw0rd!"


def test_from_options_defaults_dc_host_to_domain(resolver: FakeResolver):
    target = Target.from_options(_options())
    assert target.dc_host == "CORP.LOCAL"
    assert target.remote_name == "CORP.LOCAL"
    assert target.target_ip == "10.0.0.99"
    assert resolver.lookups == ["CORP.LOCAL"]


def test_from_options_dc_as_target_uses_dc_ip(resolver: FakeResolver):
    target = Target.from_options(_options(), dc_as_target=True)
    assert target.target_ip == "10.0.0.1"
    assert target.dc_ip == "10.0.0.1"
    assert resolver.lookups == []


def test_from_options_ip_target_sets_target_ip(resolver: FakeResolver):
    target = Target.from_options(_options(target="10.0.0.5"))
    assert target.remote_name == "10.0.0.5"
    assert target.target_ip == "10.0.0.5"


@pytest.mark.parametrize(
    ("hashes", "lm", "nt"),
    [
        (
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "aad3b435b51404eeaad3b435b51404ee",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ),
        (
            ":31d6cfe0d16ae931b73c59d7e0c089c0",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ),
        (
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
        ),
    ],
)
def test_from_options_parses_hashes(
    resolver: FakeResolver, hashes: str, lm: str, nt: str
):
    target = Target.from_options(_options(password=None, hashes=hashes))
    assert (target.lmhash, target.nthash) == (lm, nt)


def test_from_options_aes_implies_kerberos(
    resolver: FakeResolver, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    target = Target.from_options(_options(password=None, aes="00" * 32))
    assert target.do_kerberos


@pytest.mark.parametrize(("scheme", "port"), [("ldap", 389), ("ldaps", 636)])
def test_from_options_default_ldap_port(resolver: FakeResolver, scheme: str, port: int):
    target = Target.from_options(_options(ldap_scheme=scheme))
    assert target.ldap_port == port


def test_from_options_ldap_toggles(resolver: FakeResolver):
    target = Target.from_options(
        _options(no_ldap_channel_binding=True, no_ldap_signing=True)
    )
    assert not target.ldap_channel_binding
    assert not target.ldap_signing


def test_from_options_prompts_for_missing_password(
    resolver: FakeResolver, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr("getpass.getpass", lambda _prompt: "typed")
    target = Target.from_options(_options(password=None))
    assert target.password == "typed"


def test_from_options_without_any_target_raises(resolver: FakeResolver):
    with pytest.raises(Exception, match="Could not find a target"):
        Target.from_options(
            argparse.Namespace(username="alice", password="x"), require_username=True
        )


def test_kerberos_principal_none_without_ccache(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    assert target_module.get_kerberos_principal() is None


def test_from_options_kerberos_flag_skips_password_prompt(
    resolver: FakeResolver, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    target = Target.from_options(_options(password=None, do_kerberos=True))
    assert target.do_kerberos
    assert (target.username, target.domain) == ("ALICE", "CORP.LOCAL")
    assert target.password is None
