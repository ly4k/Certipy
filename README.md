# certipy-merged

This repository contains a fork of [ly4k/Certipy](https://github.com/ly4k/Certipy) with many open pull requests merged, made compatible with each other, and tested (to a certain degree).

As this is a _work in progress_, some features may or may not work as expected and things might break.

## Installation

### Using `pipx` (Recommended)

If you prefer the convenience of automagically managed virtual environments, use [`pipx`](https://github.com/pypa/pipx):

```bash
pipx install git+https://github.com/zimedev/certipy-merged.git@main
```

If you need support for LDAP Channel Binding, you need to inject the patched `ldap3` library into the Python venv:

```bash
pipx inject --force certipy-ad git+https://github.com/ly4k/ldap3
```

### Using Python `pip` With a Virtual Environment

If you want to manually manage your installation, use Python's `pip` with `venv` to install in a directory of your choosing, such as `/opt`:

```bash
cd /opt
git clone https://github.com/zimedev/certipy-merged
cd certipy-merged
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

## Merge Status

### Missing PRs:

- [ ] [#211](https://github.com/ly4k/Certipy/pull/211): fix ESC1 false positive
- [ ] [#229](https://github.com/ly4k/Certipy/pull/229): add smime extensions support (somehow does not work completely with certipy auth)

### Merged PRs:

- [X] [#238](https://github.com/ly4k/Certipy/pull/238): fix: check pKIExpirationPeriod & pKIOverlapPeriod
- [X] [#231](https://github.com/ly4k/Certipy/pull/231): add ldap simple auth
- [X] [#228](https://github.com/ly4k/Certipy/pull/228): add ESC15
- [X] [#226](https://github.com/ly4k/Certipy/pull/226): fix ESC1 false positive
- [X] [#225](https://github.com/ly4k/Certipy/pull/225): fix to solve SID overwrite errors
- [X] [#222](https://github.com/ly4k/Certipy/pull/222): fix to allow certificate names with slashes or parentheses
- [X] [#210](https://github.com/ly4k/Certipy/pull/210): add cross domain authentication
- [X] [#209](https://github.com/ly4k/Certipy/pull/209): accept tgs other than HOST/target@domain
- [X] [#203](https://github.com/ly4k/Certipy/pull/203): check web enrollment for https
- [X] [#201](https://github.com/ly4k/Certipy/pull/201): add dcom support
- [X] [#200](https://github.com/ly4k/Certipy/pull/200): add possibility to add more than 1 keycredential and correctly list them
- [X] [#198](https://github.com/ly4k/Certipy/pull/198): add ldap-port option
- [X] [#196](https://github.com/ly4k/Certipy/pull/196): add ESC13
- [X] [#193](https://github.com/ly4k/Certipy/pull/193): add whencreated and whenmodified for templates
- [X] [#183](https://github.com/ly4k/Certipy/pull/183): hidden import (pycryptodomex)

