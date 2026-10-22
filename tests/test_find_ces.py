import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from certipy.commands.find import Find


class CESFindTests(unittest.TestCase):
    def setUp(self) -> None:
        resolver = SimpleNamespace(resolve=MagicMock(return_value="192.0.2.10"))
        target: Any = SimpleNamespace(
            resolver=resolver,
            timeout=5,
            do_kerberos=False,
            remote_name="dc.test.local",
        )
        self.finder: Any = Find(target)
        self.ca: Any = {
            "name": "TEST CA",
            "dNSHostName": "ca.test.local",
        }

    def test_builds_conventional_kerberos_ces_endpoint(self) -> None:
        self.assertEqual(
            self.finder.get_ces_path(self.ca),
            "/TEST%20CA_CES_Kerberos/service.svc/CES",
        )
        self.assertEqual(
            self.finder.get_ces_endpoint(self.ca),
            "https://ca.test.local/TEST%20CA_CES_Kerberos/service.svc/CES",
        )

    def test_detects_ces_from_unauthenticated_401(self) -> None:
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value.status_code = 401

        with patch("certipy.commands.find.httpx.Client", return_value=session):
            self.assertTrue(self.finder.check_ces_enrollment(self.ca))

        session.get.assert_called_once_with(
            "https://192.0.2.10/TEST%20CA_CES_Kerberos/service.svc/CES",
            headers={
                "User-Agent": session.get.call_args.kwargs["headers"]["User-Agent"],
                "Host": "ca.test.local",
            },
            timeout=5,
            follow_redirects=False,
        )

    def test_checks_channel_binding_against_ces_path(self) -> None:
        no_cb_session = MagicMock()
        no_cb_session.get.return_value.status_code = 401
        cb_session = MagicMock()
        cb_session.get.return_value.status_code = 400

        with (
            patch("certipy.commands.find.HttpxNtlmAuth"),
            patch(
                "certipy.commands.find.httpx.Client",
                side_effect=[no_cb_session, cb_session],
            ),
        ):
            result = self.finder.check_channel_binding(
                self.ca,
                path=self.finder.get_ces_path(self.ca),
                service="CES",
            )

        self.assertTrue(result)
        expected_url = "https://192.0.2.10/TEST%20CA_CES_Kerberos/service.svc/CES"
        self.assertEqual(no_cb_session.get.call_args.args[0], expected_url)
        self.assertEqual(cb_session.get.call_args.args[0], expected_url)

    def test_reports_ces_without_channel_binding_as_esc8(self) -> None:
        ca = {
            **self.ca,
            "request_disposition": "Issue",
            "user_specified_san": "Disabled",
            "active_policy": "CertificateAuthority_MicrosoftDefault.Policy",
            "enforce_encrypt_icertrequest": "Enabled",
            "web_enrollment": {
                "http": {"enabled": False},
                "https": {"enabled": False, "channel_binding": None},
            },
            "ces": {
                "https": {
                    "enabled": True,
                    "channel_binding": False,
                    "url": "https://ca.test.local/TEST%20CA_CES_Kerberos/service.svc/CES",
                }
            },
        }

        with (
            patch.object(
                self.finder,
                "can_user_enroll_in_ca",
                return_value=(False, []),
            ),
            patch.object(
                self.finder,
                "ca_has_vulnerable_acl",
                return_value=(False, []),
            ),
        ):
            vulnerabilities, _, _, _ = self.finder.get_ca_vulnerabilities(ca)

        self.assertIn("ESC8.1", vulnerabilities)
        self.assertIn("CES", vulnerabilities["ESC8.1"])
        self.assertIn("Channel Binding is disabled", vulnerabilities["ESC8.1"])


if __name__ == "__main__":
    unittest.main()
