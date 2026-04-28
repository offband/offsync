import unittest

from offsync.sync import parse_rsync_itemize


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


if __name__ == "__main__":
    unittest.main()
