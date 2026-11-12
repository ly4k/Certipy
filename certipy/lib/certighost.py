"""Build classification helpers for CVE-2026-54121 (Certighost).

Microsoft fixed the unvalidated AD CS client-DC chase path in the July 2026
cumulative updates. The fix is build-specific, so detection compares the CA
host's CurrentBuildNumber/UBR against the fixed revision for its release
branch. An unknown branch or revision is reported as inconclusive rather than
as patched.
"""

from typing import Optional, Tuple

EDITF_ENABLECHASECLIENTDC = 0x00100000

CERTIGHOST_FIXED_BUILDS = {
    9200: 26226,  # Windows Server 2012
    9600: 23291,  # Windows Server 2012 R2
    14393: 9339,  # Windows Server 2016
    17763: 9020,  # Windows Server 2019
    20348: 5386,  # Windows Server 2022
    26100: 33158,  # Windows Server 2025
}


def parse_windows_build(build: str) -> Optional[Tuple[int, int]]:
    """Return ``(build, revision)`` from a Windows version string."""
    try:
        parts = [int(part) for part in build.split(".")]
    except (AttributeError, ValueError):
        return None

    if len(parts) == 2:
        return parts[0], parts[1]
    if len(parts) >= 4:
        return parts[-2], parts[-1]
    return None


def is_certighost_build_vulnerable(build: str) -> Optional[bool]:
    """Classify a Windows build for CVE-2026-54121.

    ``None`` means the build is unknown or is not one of the affected Windows
    Server release branches.
    """
    parsed = parse_windows_build(build)
    if parsed is None:
        return None

    build_number, revision = parsed
    fixed_revision = CERTIGHOST_FIXED_BUILDS.get(build_number)
    if fixed_revision is None:
        return None

    return revision < fixed_revision
