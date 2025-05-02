from setuptools import setup

with open("README.md") as f:
    readme = f.read()

setup(
    name="certipy-ad",
    version="4.8.2",
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
        "requests_ntlm~=1.3.0",
        'winacl~=0.1.9; platform_system=="Windows"',
        'wmi~=1.4.9; platform_system=="Windows"',
        "pycryptodome~=3.22.0",
        'unicrypto~=0.0.10; platform_system=="Windows"'
        'bs4~=0.0.2',
    ],
    packages=[
        "certipy",
        "certipy.commands",
        "certipy.commands.parsers",
        "certipy.lib",
        "certipy.lib.sspi",
    ],
    entry_points={
        "console_scripts": ["certipy=certipy.entry:main"],
    },
    description="Active Directory Certificate Services enumeration and abuse",
)
