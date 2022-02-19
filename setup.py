from setuptools import setup

setup(
    name="Certipy",
    version="2.0",
    license="MIT",
    author="ly4k",
    url="https://github.com/ly4k/Certipy",
    long_description="README.md",
    install_requires=[
        "asn1crypto",
        "cryptography",
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
    description="Python implementation for Active Directory certificate abuse",
)
