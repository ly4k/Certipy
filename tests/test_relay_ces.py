import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from certipy.commands.relay import ADCSHTTPAttackClient, Relay


class CESRelayTests(unittest.TestCase):
    def test_existing_web_enrollment_target_is_unchanged(self) -> None:
        with patch("certipy.commands.relay.SMBRelayServer"):
            relay = Relay(target="http://ca.test")

        self.assertFalse(relay.ces)
        self.assertEqual(relay.target, "http://ca.test/certsrv/certfnsh.asp")
        self.assertEqual(relay.base_url, "http://ca.test")

    def test_existing_rpc_target_is_unchanged(self) -> None:
        with patch("certipy.commands.relay.SMBRelayServer"):
            relay = Relay(target="rpc://ca.test", ca="TEST-CA")

        self.assertFalse(relay.ces)
        self.assertEqual(relay.target, "rpc://ca.test")
        self.assertEqual(relay.ca, "TEST-CA")

    def test_ces_target_keeps_path_query_and_port(self) -> None:
        target = "https://ca.test:8443/CA_CES_Kerberos/service.svc/CES?mode=test"
        with patch("certipy.commands.relay.SMBRelayServer"):
            relay = Relay(target=target, ces=True)

        self.assertEqual(relay.target, target)
        self.assertEqual(relay.base_url, "https://ca.test:8443")
        self.assertEqual(
            relay.ces_path,
            "/CA_CES_Kerberos/service.svc/CES?mode=test",
        )

    def test_ces_attack_posts_soap_and_uses_certipy_output_handler(self) -> None:
        target = "https://ca.test/CA_CES_Kerberos/service.svc/CES"
        relay = SimpleNamespace(
            target=target,
            ces_path="/CA_CES_Kerberos/service.svc/CES",
            subject=None,
            alt_dns=None,
            alt_upn=None,
            alt_sid=None,
            key_size=2048,
            application_policies=[],
            smime=None,
            out=None,
            pfx_password="password",
        )
        client = SimpleNamespace(
            user="TEST\\HOST$",
            timeout=SimpleNamespace(read=5),
            post=MagicMock(
                return_value=SimpleNamespace(content=b"response", status_code=200)
            ),
        )
        attack: Any = object.__new__(ADCSHTTPAttackClient)
        attack.adcs_relay = relay
        attack.client = client
        attack.username = "HOST$"
        attack.config = SimpleNamespace(template=None)
        attack.finish_run = MagicMock()
        certificate = MagicMock()

        with (
            patch(
                "certipy.commands.relay.parse_ces_response",
                return_value=certificate,
            ) as parse_response,
            patch("certipy.commands.relay.handle_request_response") as handler,
        ):
            attack._request_ces_certificate()

        client.post.assert_called_once()
        call = client.post.call_args
        self.assertEqual(call.args[0], relay.ces_path)
        self.assertIn(target.encode(), call.kwargs["content"])
        self.assertIn(b"<Value>Machine</Value>", call.kwargs["content"])
        parse_response.assert_called_once_with(b"response")
        handler.assert_called_once()
        self.assertIs(handler.call_args.args[0], certificate)
        self.assertEqual(handler.call_args.args[-1], "password")
        attack.finish_run.assert_called_once()

    def test_ces_rejects_unsupported_modes(self) -> None:
        target = "https://ca.test/CA_CES_Kerberos/service.svc/CES"
        with patch("certipy.commands.relay.SMBRelayServer"):
            with self.assertRaisesRegex(ValueError, "retrieval"):
                Relay(target=target, ces=True, retrieve=1)
            with self.assertRaisesRegex(ValueError, "enumeration"):
                Relay(target=target, ces=True, enum_templates=True)
            with self.assertRaisesRegex(ValueError, "Key archival"):
                Relay(target=target, ces=True, archive_key="cax.cer")


if __name__ == "__main__":
    unittest.main()
