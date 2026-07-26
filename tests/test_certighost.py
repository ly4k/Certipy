import unittest

from certipy.lib.certighost import (
    CERTIGHOST_FIXED_BUILDS,
    is_certighost_build_vulnerable,
    parse_windows_build,
)


class CertighostBuildTests(unittest.TestCase):
    def test_parse_windows_build(self) -> None:
        self.assertEqual(parse_windows_build("20348.5386"), (20348, 5386))
        self.assertEqual(parse_windows_build("10.0.26100.33158"), (26100, 33158))
        self.assertIsNone(parse_windows_build("20348"))
        self.assertIsNone(parse_windows_build("unknown"))

    def test_fixed_build_boundaries(self) -> None:
        for build, fixed_revision in CERTIGHOST_FIXED_BUILDS.items():
            with self.subTest(build=build):
                self.assertTrue(
                    is_certighost_build_vulnerable(f"{build}.{fixed_revision - 1}")
                )
                self.assertFalse(
                    is_certighost_build_vulnerable(f"{build}.{fixed_revision}")
                )
                self.assertFalse(
                    is_certighost_build_vulnerable(f"{build}.{fixed_revision + 1}")
                )

    def test_unknown_release_is_inconclusive(self) -> None:
        self.assertIsNone(is_certighost_build_vulnerable("99999.1"))


if __name__ == "__main__":
    unittest.main()
