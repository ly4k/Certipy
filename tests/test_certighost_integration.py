import argparse
import os
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from certipy.commands import certighost as certighost_command
from certipy.commands.account import Account
from certipy.commands.auth import Authenticate
from certipy.commands.certighost import Certighost
from certipy.commands.find import Find
from certipy.commands.parsers import certighost as certighost_parser
from certipy.commands.parsers import req as req_parser
from certipy.lib.certighost import (
    CertighostListenerManager,
    check_listener_ports_available,
    redacting_smb_logger,
)


class _BlockingListener:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.stop_event = threading.Event()
        self.stopped = False

    def serve(self, ready_event: threading.Event | None = None) -> None:
        if self.error is not None:
            raise self.error
        if ready_event is not None:
            ready_event.set()
        self.stop_event.wait(2)

    def stop(self) -> None:
        self.stopped = True
        self.stop_event.set()


def _target() -> SimpleNamespace:
    return SimpleNamespace(
        dc_ip="192.0.2.10",
        domain="corp.local",
        username="user",
        password="password",
        hashes=None,
        lmhash="",
        nthash="",
        remote_name="192.0.2.10",
        target_ip="192.0.2.10",
        do_kerberos=False,
        resolver=MagicMock(),
    )


class CertighostParserTests(unittest.TestCase):
    def test_certighost_uses_certificate_only_interface(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="action")
        certighost_parser.add_subparser(subparsers)
        action = subparsers.choices["certighost"]

        self.assertNotIn("-auth", action._option_string_actions)
        self.assertNotIn("-get-hash", action._option_string_actions)
        self.assertNotIn("-ldap-shell", action._option_string_actions)
        self.assertIn("-out", action._option_string_actions)
        self.assertIn("-dc-ip", action._option_string_actions)

    def test_req_does_not_expose_arbitrary_request_attributes(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="action")
        req_parser.add_subparser(subparsers)
        action = subparsers.choices["req"]

        self.assertNotIn("-attribute", action._option_string_actions)


class AccountTemporaryLifecycleTests(unittest.TestCase):
    def test_close_temporary_deletes_with_retained_samr_handle(self) -> None:
        account = Account(_target(), user="GHOSTTEST$", passw="Secret123!")  # type: ignore[arg-type]
        dce = MagicMock()
        user_handle = object()
        domain_handle = object()
        server_handle = object()
        account._samr_dce = dce
        account._samr_user_handle = user_handle
        account._samr_domain_handle = domain_handle
        account._samr_server_handle = server_handle

        with (
            patch("certipy.commands.account.samr.hSamrDeleteUser") as delete_user,
            patch("certipy.commands.account.samr.hSamrCloseHandle") as close_handle,
        ):
            self.assertTrue(account.close_temporary(delete=True))

        delete_user.assert_called_once_with(dce, user_handle)
        self.assertEqual(
            close_handle.call_args_list,
            [
                unittest.mock.call(dce, domain_handle),
                unittest.mock.call(dce, server_handle),
            ],
        )
        dce.disconnect.assert_called_once_with()


class CertighostListenerTests(unittest.TestCase):
    def test_smb_log_redaction_preserves_keyword_arguments(self) -> None:
        original_log = MagicMock()
        conn_data = {"ClientIP": "192.0.2.20"}
        safe_log = redacting_smb_logger(original_log)

        safe_log(
            "USER::DOMAIN:0123456789abcdef:response",
            10,
            connData=conn_data,
        )

        original_log.assert_called_once_with(
            "NTLM authentication response redacted",
            10,
            connData=conn_data,
        )

    def test_port_preflight_reports_only_occupied_ports(self) -> None:
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.bind(("127.0.0.1", 0))
        port = occupied.getsockname()[1]
        try:
            self.assertEqual(
                check_listener_ports_available("127.0.0.1", (port,)), [port]
            )
        finally:
            occupied.close()

        self.assertEqual(check_listener_ports_available("127.0.0.1", (port,)), [])

    def test_manager_starts_and_stops_both_listeners(self) -> None:
        ldap = _BlockingListener()
        smb = _BlockingListener()
        manager = CertighostListenerManager(ldap, smb)  # type: ignore[arg-type]

        manager.start(timeout=1)
        manager.stop()

        self.assertTrue(ldap.stopped)
        self.assertTrue(smb.stopped)

    def test_manager_surfaces_background_startup_failure(self) -> None:
        ldap = _BlockingListener(RuntimeError("bind failed"))
        smb = _BlockingListener()
        manager = CertighostListenerManager(ldap, smb)  # type: ignore[arg-type]

        with self.assertRaisesRegex(RuntimeError, "LDAP listener failed: bind failed"):
            manager.start(timeout=1)

        self.assertTrue(ldap.stopped)
        self.assertTrue(smb.stopped)


class CertighostCommandTests(unittest.TestCase):
    def _exploit(self) -> Certighost:
        exploit = Certighost(_target(), out="dc01")
        exploit._connection = SimpleNamespace(domain_sid="S-1-5-21-1-2-3")
        exploit.created_computer = True
        exploit.computer_name = "GHOSTTEST$"
        return exploit

    def _run_with_request_result(self, request_result: object):
        exploit = self._exploit()
        target_entry = {
            "sAMAccountName": "DC01$",
            "dNSHostName": "dc01.corp.local",
        }
        manager = MagicMock()
        request = MagicMock()
        request.request.return_value = request_result
        events = MagicMock()
        events.attach_mock(manager.stop, "listeners_stopped")

        cleanup = MagicMock()
        events.attach_mock(cleanup, "account_cleaned")

        patches = (
            patch.object(exploit, "_discover_target", return_value=target_entry),
            patch.object(exploit, "_sid_bytes", return_value=b"sid"),
            patch.object(
                exploit,
                "_discover_ca",
                return_value=("CORP-CA", "ca.corp.local", "192.0.2.20"),
            ),
            patch.object(
                exploit,
                "_prepare_computer",
                return_value=("GHOSTTEST$", "Secret123!", "a" * 32),
            ),
            patch.object(exploit, "_domain_guid", return_value=b"0" * 16),
            patch.object(exploit, "_cleanup", cleanup),
            patch.object(
                certighost_command,
                "check_listener_ports_available",
                return_value=[],
            ),
            patch.object(certighost_command, "RogueLDAP"),
            patch.object(certighost_command, "SMBLSAListener"),
            patch.object(
                certighost_command,
                "CertighostListenerManager",
                return_value=manager,
            ),
            patch.object(certighost_command, "Request", return_value=request),
        )

        for active_patch in patches:
            active_patch.start()
        self.addCleanup(lambda: [active_patch.stop() for active_patch in patches])
        return exploit, request, manager, events

    def test_discovers_selected_ca_and_resolves_its_host(self) -> None:
        target = _target()
        target.resolver.resolve.return_value = "192.0.2.20"
        exploit = Certighost(target, ca="CORP-CA")  # type: ignore[arg-type]
        connection = MagicMock()
        connection.configuration_path = "CN=Configuration,DC=corp,DC=local"
        connection.search.return_value = [
            {"cn": "CORP-CA", "dNSHostName": "ca.corp.local"}
        ]
        exploit._connection = connection

        self.assertEqual(
            exploit._discover_ca(),
            ("CORP-CA", "ca.corp.local", "192.0.2.20"),
        )
        self.assertIn("(cn=CORP-CA)", connection.search.call_args.args[0])
        target.resolver.resolve.assert_called_once_with("ca.corp.local")

    def test_discovers_requested_target_computer(self) -> None:
        exploit = Certighost(_target(), target_account="DC02")  # type: ignore[arg-type]
        connection = MagicMock()
        expected = {
            "sAMAccountName": "DC02$",
            "dNSHostName": "dc02.corp.local",
        }
        connection.search.return_value = [expected]
        exploit._connection = connection

        self.assertIs(exploit._discover_target(), expected)
        self.assertIn("(sAMAccountName=DC02$)", connection.search.call_args.args[0])

    @patch.object(certighost_command, "detect_listener_ip", return_value="192.0.2.30")
    def test_listener_start_failure_still_stops_and_cleans_up(self, _detect) -> None:
        exploit, _, manager, events = self._run_with_request_result(False)
        manager.start.side_effect = RuntimeError("bind failed")

        with self.assertRaisesRegex(RuntimeError, "bind failed"):
            exploit.run()

        self.assertEqual(
            events.mock_calls[-2:],
            [
                unittest.mock.call.listeners_stopped(),
                unittest.mock.call.account_cleaned(),
            ],
        )

    @patch.object(certighost_command, "detect_listener_ip", return_value="192.0.2.30")
    def test_interruption_still_stops_and_cleans_up(self, _detect) -> None:
        exploit, request, _, events = self._run_with_request_result(False)
        request.request.side_effect = KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            exploit.run()

        self.assertEqual(
            events.mock_calls[-2:],
            [
                unittest.mock.call.listeners_stopped(),
                unittest.mock.call.account_cleaned(),
            ],
        )

    def test_no_cleanup_closes_handle_without_deleting_account(self) -> None:
        exploit = self._exploit()
        temporary_account = MagicMock()
        exploit._temporary_account = temporary_account
        exploit.no_cleanup = True

        exploit._cleanup()

        temporary_account.close_temporary.assert_called_once_with(delete=False)

    @patch.object(certighost_command, "detect_listener_ip", return_value="192.0.2.30")
    def test_request_uses_internal_attributes_and_exact_output_path(
        self, _detect
    ) -> None:
        exploit, request, manager, events = self._run_with_request_result(
            (b"pfx-data", "dc01_2.pfx")
        )

        with patch.object(certighost_command.logging, "info") as log_info:
            self.assertTrue(exploit.run())

        request_kwargs = certighost_command.Request.call_args.kwargs
        self.assertEqual(
            request_kwargs["additional_attributes"],
            ["cdc:192.0.2.30", "rmd:dc01.corp.local"],
        )
        self.assertNotIn("attribute", request_kwargs)
        self.assertFalse(request_kwargs["prompt_for_pending_key"])
        self.assertTrue(
            any("dc01_2.pfx" in call.args[0] for call in log_info.call_args_list)
        )
        manager.raise_if_failed.assert_called_once_with()
        self.assertEqual(
            events.mock_calls[-2:],
            [
                unittest.mock.call.listeners_stopped(),
                unittest.mock.call.account_cleaned(),
            ],
        )

    @patch.object(certighost_command, "detect_listener_ip", return_value="192.0.2.30")
    def test_request_failure_still_stops_and_cleans_up(self, _detect) -> None:
        exploit, _, manager, events = self._run_with_request_result(False)

        self.assertFalse(exploit.run())

        manager.stop.assert_called_once_with()
        self.assertEqual(
            events.mock_calls[-2:],
            [
                unittest.mock.call.listeners_stopped(),
                unittest.mock.call.account_cleaned(),
            ],
        )

    @patch.object(certighost_command, "detect_listener_ip", return_value="192.0.2.30")
    def test_preflight_failure_happens_before_account_creation(self, _detect) -> None:
        exploit = self._exploit()
        with (
            patch.object(
                exploit,
                "_discover_target",
                return_value={
                    "sAMAccountName": "DC01$",
                    "dNSHostName": "dc01.corp.local",
                },
            ),
            patch.object(exploit, "_sid_bytes", return_value=b"sid"),
            patch.object(
                exploit,
                "_discover_ca",
                return_value=("CORP-CA", "ca.corp.local", "192.0.2.20"),
            ),
            patch.object(exploit, "_prepare_computer") as prepare,
            patch.object(
                certighost_command,
                "check_listener_ports_available",
                return_value=[389],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "389"):
                exploit.run()
        prepare.assert_not_called()


class CertighostFindTests(unittest.TestCase):
    def _classify(self, chase: str, build: str):
        finder = Find.__new__(Find)
        finder.can_user_enroll_in_ca = MagicMock(return_value=(False, []))
        finder.format_principals = MagicMock(return_value=[])
        finder.ca_has_vulnerable_acl = MagicMock(return_value=(False, []))
        ca = {
            "client_dc_chase": chase,
            "windows_build": build,
            "request_disposition": "Issue",
            "web_enrollment": None,
        }
        return finder.get_ca_vulnerabilities(ca)

    def test_find_classifies_vulnerable_patched_disabled_and_unknown(self) -> None:
        vulnerabilities, remarks, _, _ = self._classify("Enabled", "17763.9019")
        self.assertIn("CVE-2026-54121", vulnerabilities)
        self.assertIn("CVE-2026-54121", remarks)

        vulnerabilities, remarks, _, _ = self._classify("Enabled", "17763.9020")
        self.assertNotIn("CVE-2026-54121", vulnerabilities)
        self.assertNotIn("CVE-2026-54121", remarks)

        vulnerabilities, remarks, _, _ = self._classify("Disabled", "17763.9019")
        self.assertNotIn("CVE-2026-54121", vulnerabilities)
        self.assertNotIn("CVE-2026-54121", remarks)

        vulnerabilities, remarks, _, _ = self._classify("Enabled", "Unknown")
        self.assertNotIn("CVE-2026-54121", vulnerabilities)
        self.assertIn("CVE-2026-54121", remarks)

        vulnerabilities, remarks, _, _ = self._classify("Unknown", "Unknown")
        self.assertNotIn("CVE-2026-54121", vulnerabilities)
        self.assertNotIn("CVE-2026-54121", remarks)


class CertighostAuthenticationCompatibilityTests(unittest.TestCase):
    def test_saved_pfx_bytes_are_passed_unchanged_to_authenticate(self) -> None:
        pfx_data = b"certighost-pfx"
        handle = tempfile.NamedTemporaryFile(delete=False)
        try:
            handle.write(pfx_data)
            handle.close()
            key = object()
            certificate = object()
            with patch(
                "certipy.commands.auth.load_pfx", return_value=(key, certificate)
            ) as load_pfx:
                authenticate = Authenticate(_target(), pfx=handle.name)

            load_pfx.assert_called_once_with(pfx_data, None)
            self.assertIs(authenticate.key, key)
            self.assertIs(authenticate.cert, certificate)
        finally:
            handle.close()
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
