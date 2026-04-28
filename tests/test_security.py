import unittest
from unittest.mock import patch

from offsync.config import Target
from offsync.ssh import (
    OffsyncError,
    build_authorized_keys_entry,
    known_hosts_fingerprint,
    parse_login,
    verify_restricted_rsync,
)


class SecurityTests(unittest.TestCase):
    def test_restricted_authorized_keys_entry(self):
        entry = build_authorized_keys_entry("ssh-ed25519 AAAA offsync@test", "/home/user/.offsync/sync")

        self.assertIn('command="/usr/bin/rrsync -wo /home/user/.offsync/sync"', entry)
        self.assertIn("no-port-forwarding", entry)
        self.assertIn("no-agent-forwarding", entry)
        self.assertIn("no-X11-forwarding", entry)
        self.assertIn("no-pty", entry)
        self.assertTrue(entry.endswith("ssh-ed25519 AAAA offsync@test"))

    def test_rejects_path_traversal(self):
        with self.assertRaises(OffsyncError):
            build_authorized_keys_entry("ssh-ed25519 AAAA offsync@test", "/home/user/../root")

    def test_rejects_invalid_public_key_prefix(self):
        with self.assertRaises(OffsyncError):
            build_authorized_keys_entry('command="sh" ssh-ed25519 AAAA offsync@test', "/srv/data")

    def test_rejects_invalid_public_key_data(self):
        with self.assertRaises(OffsyncError):
            build_authorized_keys_entry("ssh-ed25519 not-base64! offsync@test", "/srv/data")

    def test_rejects_unsafe_target_login(self):
        for login in ("deploy@example.test:/tmp", "deploy@-oProxyCommand=sh", "bad/user@example.test"):
            with self.subTest(login=login):
                with self.assertRaises(OffsyncError):
                    parse_login(login)

    def test_custom_rrsync_path(self):
        entry = build_authorized_keys_entry(
            "ssh-ed25519 AAAA offsync@test",
            "/srv/data",
            "/usr/lib/rsync/rrsync",
        )

        self.assertIn('command="/usr/lib/rsync/rrsync -wo /srv/data"', entry)

    def test_known_hosts_fingerprint(self):
        fingerprint = known_hosts_fingerprint("example.test ssh-ed25519 YWJj\n")

        self.assertEqual(fingerprint, "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0")

    def test_verify_restricted_rsync_uses_batch_key_command(self):
        target = Target(
            login="deploy@example.test",
            user="deploy",
            host="example.test",
            remote_path="/srv/data",
        )

        with patch("offsync.ssh.run") as run:
            verify_restricted_rsync(target)

        args = run.call_args.args[0]
        self.assertEqual(args[0], "rsync")
        self.assertIn("--dry-run", args)
        self.assertIn("--checksum", args)
        self.assertIn("deploy@example.test:/srv/data/", args)
        self.assertIn("BatchMode=yes", args[2])


if __name__ == "__main__":
    unittest.main()
