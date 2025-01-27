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

### On Arch Linux

If you're on Arch Linux, you can add the [dadevel/archpkgs](https://github.com/dadevel/archpkgs) repository, which defaults to `certipy-merged` and includes LDAP Channel Binding support out of the box.
To add the `archpkgs` repo, refer to the official [setup instructions](https://github.com/dadevel/archpkgs?tab=readme-ov-file#setup).
Next, you can install `archpkgs/certipy`:

```bash
sudo pacman -Sy archpkgs/certipy
```

```bash
/opt/archpkgs/bin/certipy                                                     
Certipy v4.8.2 - by Oliver Lyak (ly4k)

usage: certipy [-v] [-h] {account,auth,ca,cert,find,forge,ptt,relay,req,shadow,template} ...

Active Directory Certificate Services enumeration and abuse

positional arguments:
  {account,auth,ca,cert,find,forge,ptt,relay,req,shadow,template}
                        Action
    account             Manage user and machine accounts
    auth                Authenticate using certificates
    ca                  Manage CA and certificates
    cert                Manage certificates and private keys
    find                Enumerate AD CS
    forge               Create Golden Certificates
    ptt                 Inject TGT for SSPI authentication
    relay               NTLM Relay to AD CS HTTP Endpoints
    req                 Request certificates
    shadow              Abuse Shadow Credentials for account takeover
    template            Manage certificate templates

options:
  -v, --version         Show Certipy's version number and exit
  -h, --help            Show this help message and exit
```

## Merge Status

### Missing PRs:

- [ ] [#211](https://github.com/ly4k/Certipy/pull/211): fix ESC1 false positive
- [ ] [#229](https://github.com/ly4k/Certipy/pull/229): add smime extensions support (somehow does not work completely with certipy auth)

### Merged PRs:

- [X] [#248](https://github.com/ly4k/Certipy/pull/248): fix subject in generated certificate of shadow credentials
- [X] [#247](https://github.com/ly4k/Certipy/pull/247): add parse sub command to perform stealthy offline ADCS enumeration
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

