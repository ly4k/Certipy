from setuptools import setup

with open("README.md") as f:
    readme = f.read()

_ = setup(
    name="certipy-ad",
    version="5.0.0",
    license="MIT",
    author="ly4k",
    url="https://github.com/ly4k/Certipy",
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=[
        "asn1crypto~=1.5.1",
        "cryptography~=42.0.8",
        "impacket~=0.12.0",
        "ldap3~=2.9.1",
        "pyasn1~=0.6.1",
        "dnspython~=2.7.0",
        "dsinternals~=1.2.4",
        "pyopenssl~=24.0.0",
        "requests~=2.32.3",
        "pycryptodome~=3.22.0",
        "bs4~=0.0.2",
        "httpx~=0.28.1",
        "httpx-ntlm~=1.4.0",
    ],
    packages=[
        "certipy",
        "certipy.commands",
        "certipy.commands.parsers",
        "certipy.lib",
    ],
    entry_points={
        "console_scripts": ["certipy=certipy.entry:main"],
    },
    description="Active Directory Certificate Services enumeration and abuse",
)
