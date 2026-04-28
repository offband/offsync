from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .config import offsync_home


def log_operation(host: str, operation: str, files: Iterable[str]) -> None:
    log_path = offsync_home() / "operations.log"
    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "host": host,
        "operation": operation,
        "files_changed": sorted(files),
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    log_path.chmod(0o600)
