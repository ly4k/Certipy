# certipy-merged

This repository contains a fork of [ly4k/Certipy](https://github.com/ly4k/Certipy) with many open pull requests merged, made compatible with each other, and tested (to a certain degree).

As this is a _work in progress_, some features may or may not work as expected and things might break.

## Installation

Using `pipx`:

```bash
pipx install git+https://github.com/zimedev/certipy-merged.git@main
```

If you need support for LDAP Channel Binding, you need to inject the patched `ldap3` library into the Python venv:

```bash
pipx inject --force certipy-ad git+https://github.com/ly4k/ldap3
```

## Merge Status

### Missing PRs:

- 211: fix ESC1 false positive
- 229: add smime extensions support (somehow does not work completely with certipy auth)

### Merged PRs:

- 231: add ldap simple auth
- 228: add ESC15
- 226: fix ESC1 false positive
- 225: fix to solve SID overwrite errors
- 222: fix to allow certificate names with slashes or parentheses
- 210: add cross domain authentication
- 209: accept tgs other than HOST/target@domain
- 203: check web enrollment for https
- 201: add dcom support
- 200: add possibility to add more than 1 keycredential and correctly list them
- 198: add ldap-port option
- 196: add ESC13
- 193: add whencreated and whenmodified for templates
- 183: hidden import (pycryptodomex)
