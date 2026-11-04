import argparse

import pytest

from certipy.commands.parsers import ENTRY_PARSERS


@pytest.fixture(scope="module")
def parser() -> argparse.ArgumentParser:
    """Top-level parser built the same way certipy.entry.main builds it."""
    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for entry_parser in ENTRY_PARSERS:
        entry_parser.add_subparser(subparsers)
    return parser


MINIMAL_ARGV = {
    "account": ["read", "-user", "bob"],
    "auth": ["-pfx", "admin.pfx"],
    "ca": [],
    "cert": [],
    "find": [],
    "parse": ["dump.reg"],
    "forge": [],
    "relay": ["-target", "http://ca.corp.local"],
    "req": [],
    "shadow": ["list"],
    "template": ["-template", "User"],
}

REQUIRES_ARGUMENTS = [name for name, argv in MINIMAL_ARGV.items() if argv]


def test_every_entry_parser_is_covered():
    names = {entry_parser.NAME for entry_parser in ENTRY_PARSERS}
    assert names == set(MINIMAL_ARGV)


@pytest.mark.parametrize("action", sorted(MINIMAL_ARGV))
def test_minimal_argv_parses(parser: argparse.ArgumentParser, action: str):
    options = parser.parse_args([action, *MINIMAL_ARGV[action]])
    assert options.action == action


@pytest.mark.parametrize("action", REQUIRES_ARGUMENTS)
def test_missing_required_arguments_exit(parser: argparse.ArgumentParser, action: str):
    with pytest.raises(SystemExit):
        parser.parse_args([action])


def test_unknown_action_exits(parser: argparse.ArgumentParser):
    with pytest.raises(SystemExit):
        parser.parse_args(["nope"])


@pytest.mark.parametrize(
    ("action", "argv"),
    [
        ("account", ["explode", "-user", "bob"]),
        ("shadow", ["explode"]),
        ("auth", ["-pfx", "a.pfx", "-ldap-scheme", "http"]),
        ("req", ["-web", "-http-scheme", "ftp"]),
        ("parse", ["dump.reg", "-format", "xml"]),
    ],
)
def test_invalid_choices_exit(
    parser: argparse.ArgumentParser, action: str, argv: list[str]
):
    with pytest.raises(SystemExit):
        parser.parse_args([action, *argv])


def test_target_options_land_on_namespace(parser: argparse.ArgumentParser):
    options = parser.parse_args(
        [
            "find",
            "-u",
            "alice@corp.local",
            "-hashes",
            ":31d6cfe0d16ae931b73c59d7e0c089c0",
            "-k",
            "-dc-ip",
            "10.0.0.1",
            "-ldap-scheme",
            "ldap",
        ]
    )
    assert options.username == "alice@corp.local"
    assert options.hashes == ":31d6cfe0d16ae931b73c59d7e0c089c0"
    assert options.do_kerberos is True
    assert options.dc_ip == "10.0.0.1"
    assert options.ldap_scheme == "ldap"
