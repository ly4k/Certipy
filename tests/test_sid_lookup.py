from typing import Any, Callable, Dict, List, Optional, cast

import pytest

from certipy.lib import sid_lookup
from certipy.lib.ldap import LDAPConnection, LDAPEntry
from certipy.lib.sid_lookup import dc_target, lookup_object_sid, resolve_alt_sid
from certipy.lib.target import DnsResolver, Target

ADMIN_SID = "S-1-5-21-1-2-3-500"
DC_SID = "S-1-5-21-1-2-3-1001"


@pytest.fixture(autouse=True)
def _propagate_certipy_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sid_lookup.logging, "propagate", True)


class FakeConnection:
    def __init__(
        self,
        by_filter: Optional[Dict[str, List[LDAPEntry]]] = None,
        users: Optional[Dict[str, LDAPEntry]] = None,
        connect_error: Optional[Exception] = None,
        search_error: Optional[Exception] = None,
    ) -> None:
        self.by_filter = by_filter or {}
        self.users = users or {}
        self.connect_error = connect_error
        self.search_error = search_error
        self.filters: List[str] = []
        self.user_lookups: List[str] = []

    def connect(self) -> None:
        if self.connect_error:
            raise self.connect_error

    def search(self, search_filter: str, *args: Any, **kwargs: Any) -> List[LDAPEntry]:
        self.filters.append(search_filter)
        if self.search_error:
            raise self.search_error
        return self.by_filter.get(search_filter, [])

    def get_user(self, username: str, silent: bool = False) -> Optional[LDAPEntry]:
        self.user_lookups.append(username)
        return self.users.get(username)


def _conn(fake: FakeConnection) -> LDAPConnection:
    return cast(LDAPConnection, fake)


def _target(**overrides: Any) -> Target:
    values: Dict[str, Any] = dict(
        domain="CORP.LOCAL",
        username="LOWPRIV",
        password="Passw0rd!",
        remote_name="ca.corp.local",
        target_ip="10.0.0.20",
        dc_host="dc01.corp.local",
        dc_ip="10.0.0.10",
    )
    values.update(overrides)
    return Target(DnsResolver.create(), **values)


def test_upn_found_by_user_principal_name(
    make_ldap_entry: Callable[..., LDAPEntry],
) -> None:
    fake = FakeConnection(
        by_filter={
            "(userPrincipalName=administrator@corp.local)": [
                make_ldap_entry({"objectSid": ADMIN_SID})
            ]
        }
    )
    assert lookup_object_sid(_conn(fake), upn="administrator@corp.local") == ADMIN_SID
    assert fake.user_lookups == []


def test_upn_falls_back_to_sam_account_name(
    make_ldap_entry: Callable[..., LDAPEntry],
) -> None:
    fake = FakeConnection(
        users={"administrator": make_ldap_entry({"objectSid": ADMIN_SID})}
    )
    assert lookup_object_sid(_conn(fake), upn="administrator@corp.local") == ADMIN_SID
    assert fake.user_lookups == ["administrator"]


def test_upn_takes_precedence_over_dns(
    make_ldap_entry: Callable[..., LDAPEntry],
) -> None:
    fake = FakeConnection(
        by_filter={
            "(userPrincipalName=administrator@corp.local)": [
                make_ldap_entry({"objectSid": ADMIN_SID})
            ]
        }
    )
    sid = lookup_object_sid(
        _conn(fake), upn="administrator@corp.local", dns="dc01.corp.local"
    )
    assert sid == ADMIN_SID
    assert not any("dNSHostName" in f for f in fake.filters)


def test_dns_found_by_computer_dns_host_name(
    make_ldap_entry: Callable[..., LDAPEntry],
) -> None:
    fake = FakeConnection(
        by_filter={
            "(&(objectClass=computer)(dNSHostName=dc01.corp.local))": [
                make_ldap_entry({"objectSid": DC_SID})
            ]
        }
    )
    assert lookup_object_sid(_conn(fake), dns="dc01.corp.local") == DC_SID


def test_filter_values_are_escaped() -> None:
    fake = FakeConnection()
    lookup_object_sid(_conn(fake), upn="a*)(x@corp.local")
    assert fake.filters == ["(userPrincipalName=a\\2a\\29\\28x@corp.local)"]
    assert fake.user_lookups == ["a\\2a\\29\\28x"]


def test_not_found_returns_none_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeConnection()
    assert lookup_object_sid(_conn(fake), upn="ghost@corp.local") is None
    assert "ghost@corp.local" in caplog.text


def test_nothing_to_look_up_does_not_search() -> None:
    fake = FakeConnection()
    assert lookup_object_sid(_conn(fake)) is None
    assert fake.filters == []


def test_dc_target_points_at_domain_controller() -> None:
    original = _target()
    dc = dc_target(original)
    assert dc.remote_name == "dc01.corp.local"
    assert dc.target_ip == "10.0.0.10"
    assert dc.username == "LOWPRIV"
    # the caller's target is untouched
    assert original.remote_name == "ca.corp.local"
    assert original.target_ip == "10.0.0.20"


def test_resolve_explicit_sid_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sid_lookup, "LDAPConnection", lambda *_a, **_k: pytest.fail("no LDAP")
    )
    assert (
        resolve_alt_sid(_target(), "administrator@corp.local", None, "S-1-5-21-9")
        == "S-1-5-21-9"
    )


def test_resolve_without_upn_or_dns_skips_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sid_lookup, "LDAPConnection", lambda *_a, **_k: pytest.fail("no LDAP")
    )
    assert resolve_alt_sid(_target(), None, None, None) is None


def test_resolve_without_credentials_skips_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sid_lookup, "LDAPConnection", lambda *_a, **_k: pytest.fail("no LDAP")
    )
    assert resolve_alt_sid(None, "administrator@corp.local", None, None) is None
    assert (
        resolve_alt_sid(_target(username=""), "administrator@corp.local", None, None)
        is None
    )


def test_resolve_looks_up_against_dc(
    monkeypatch: pytest.MonkeyPatch, make_ldap_entry: Callable[..., LDAPEntry]
) -> None:
    seen: List[Target] = []
    fake = FakeConnection(
        by_filter={
            "(userPrincipalName=administrator@corp.local)": [
                make_ldap_entry({"objectSid": ADMIN_SID})
            ]
        }
    )

    def factory(target: Target) -> FakeConnection:
        seen.append(target)
        return fake

    monkeypatch.setattr(sid_lookup, "LDAPConnection", factory)
    sid = resolve_alt_sid(_target(), "administrator@corp.local", None, None)
    assert sid == ADMIN_SID
    assert seen[0].target_ip == "10.0.0.10"


@pytest.mark.parametrize("where", ["connect", "search"])
def test_resolve_failure_is_non_fatal(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, where: str
) -> None:
    error = RuntimeError("ldap down")
    fake = FakeConnection(
        connect_error=error if where == "connect" else None,
        search_error=error if where == "search" else None,
    )
    monkeypatch.setattr(sid_lookup, "LDAPConnection", lambda _t: fake)
    assert resolve_alt_sid(_target(), "administrator@corp.local", None, None) is None
    assert "ldap down" in caplog.text
