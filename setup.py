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
        "asn1crypto",
        "cryptography>=39.0",
        "impacket",
        "ldap3",
        "pyasn1==0.4.8",
        "dnspython",
        "dsinternals",
        "pyopenssl>=23.0.0",
        "requests",
        "requests_ntlm",
        'winacl; platform_system=="Windows"',
        'wmi; platform_system=="Windows"',
        "pycryptodome",
        "unicrypto"
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
