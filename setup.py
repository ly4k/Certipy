from setuptools import setup

setup(
    name="Certipy",
    version="2.0.9",
    license="MIT",
    author="ly4k",
    url="https://github.com/ly4k/Certipy",
    long_description="README.md",
    install_requires=[
        "asn1crypto",
        "cryptography>=3.5",
        "impacket",
        "ldap3",
        "pyasn1",
        "dnspython",
        "dsinternals",
        "pyopenssl",
    ],
    packages=["certipy"],
    entry_points={
        "console_scripts": ["certipy=certipy.entry:main"],
    },
    description="Active Directory Certificate Services enumeration and abuse",
)
