import os
import tempfile
import unittest
from pathlib import Path

from offsync.target import install_controller_key, target_from_login


class TargetTests(unittest.TestCase):
    def test_install_controller_key_writes_restricted_authorized_key(self):
        old_home = os.environ.get("HOME")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["HOME"] = tmp
                fake_rrsync = Path(tmp) / "rrsync"
                fake_rrsync.write_text("#!/bin/sh\n", encoding="utf-8")
                fake_rrsync.chmod(0o755)

                allowed = install_controller_key(
                    "ssh-ed25519 AAAA offsync@test",
                    "~/data",
                    str(fake_rrsync),
                )

                authorized_keys = Path(tmp) / ".ssh" / "authorized_keys"
                contents = authorized_keys.read_text(encoding="utf-8")
                self.assertEqual(allowed, str((Path(tmp) / "data").resolve()))
                self.assertIn(f'command="{fake_rrsync} -wo {allowed}"', contents)
                self.assertIn("no-port-forwarding", contents)
                self.assertIn("offsync:", contents)
        finally:
            if old_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = old_home

    def test_target_from_login(self):
        target = target_from_login("deploy@example.test", "/srv/data")

        self.assertEqual(target.user, "deploy")
        self.assertEqual(target.host, "example.test")
        self.assertEqual(target.remote_path, "/srv/data")


if __name__ == "__main__":
    unittest.main()
