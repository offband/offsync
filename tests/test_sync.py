import unittest
from unittest.mock import patch

from offsync.config import Target, default_config
from offsync.sync import parse_rsync_delete_output, parse_rsync_itemize, parse_rsync_name_output, rsync_remote_spec
from offsync.sync import _rsync_common


class SyncTests(unittest.TestCase):
    def test_parse_added_and_modified_files(self):
        output = "\n".join(
            [
                ">f+++++++++ new.txt",
                ">fcst...... changed.txt",
                "*deleting   stale.txt",
                "cd+++++++++ folder/",
                ".d..t...... existing_dir/",
            ]
        )

        changes = parse_rsync_itemize(output)

        self.assertEqual(
            [(item.status, item.path) for item in changes],
            [("modified", "changed.txt"), ("added", "new.txt"), ("missing", "stale.txt")],
        )

    def test_rsync_common_uses_rrsync_safe_options(self):
        with patch("offsync.ssh.rsync_path", return_value="rsync"):
            args = _rsync_common(default_config())

        self.assertIn("--safe-links", args)
        self.assertIn("--exclude=.git/", args)
        self.assertNotIn("--human-readable", args)
        self.assertNotIn("--itemize-changes", args)

    def test_parse_rsync_name_output(self):
        output = "\n".join(
            [
                "Transfer starting: 3 files",
                "created directory /tmp/target",
                'ignoring unsafe symlink "venv/bin/python3.14" -> "/opt/homebrew/bin/python3.14"',
                "new.txt",
                "folder/",
                "changed.txt",
                "sent 82 bytes  received 20 bytes  92727 bytes/sec",
                "total size is 1  speedup is 0.01",
            ]
        )

        self.assertEqual(parse_rsync_name_output(output), {"changed.txt", "new.txt"})

    def test_parse_rsync_delete_output(self):
        output = "\n".join(["Transfer starting: 1 files", "deleting stale.txt", "*deleting old.txt"])

        self.assertEqual(parse_rsync_delete_output(output), {"old.txt", "stale.txt"})

    def test_rsync_remote_spec_uses_restricted_directory_root(self):
        target = Target(
            login="deploy@example.test",
            user="deploy",
            host="example.test",
            remote_path="/srv/data",
        )

        self.assertEqual(rsync_remote_spec(target), "deploy@example.test:.")


if __name__ == "__main__":
    unittest.main()
