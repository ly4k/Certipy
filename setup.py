from setuptools import setup

setup(
    name="Certipy",
    version="0.2",
    license="MIT",
    author="ly4k",
    url="https://github.com/ly4k/Certipy",
    long_description="README.md",
    install_requires=[
        "asn1crypto",
        "pycryptodome",
        "impacket",
        "ldap3",
        "pyasn1",
        "dnspython",
    ],
    packages=["certipy"],
    entry_points={
        "console_scripts": ["certipy=certipy.entry:main"],
    },
    description="Python implementation for Active Directory certificate abuse",
)
