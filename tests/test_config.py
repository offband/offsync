import tempfile
import unittest
from pathlib import Path

from offsync.config import Target, add_or_update_target, default_config, load_config, save_config


class ConfigTests(unittest.TestCase):
    def test_round_trip_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            config = default_config(tmp)
            add_or_update_target(
                config,
                Target(
                    login="user@example.test",
                    user="user",
                    host="example.test",
                    remote_path="/home/user/.offsync/sync",
                ),
            )
            save_config(config, path)
            loaded = load_config(path)

        self.assertEqual(loaded.source, str(Path(tmp).resolve()))
        self.assertFalse(loaded.delete)
        self.assertTrue(loaded.overwrite)
        self.assertEqual(loaded.verify, "hash")
        self.assertEqual(loaded.targets[0].login, "user@example.test")


if __name__ == "__main__":
    unittest.main()
