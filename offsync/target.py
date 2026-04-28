from __future__ import annotations

import getpass
import hashlib
import os
import shlex
import socket
from pathlib import Path

from .config import Target
from .ssh import OffsyncError, build_authorized_keys_entry, parse_login, validate_remote_path, validate_rrsync_path


def controller_public_key_text() -> str:
    print("Paste controller public key, then press Enter.")
    value = input("controller key: ").strip()
    if not value:
        raise OffsyncError("controller public key is required")
    return value


def install_controller_key(public_key: str, path: str, rrsync: str = "/usr/bin/rrsync") -> str:
    validate_rrsync_path(rrsync)
    if not os.access(rrsync, os.X_OK):
        raise OffsyncError(f"rrsync is not executable: {rrsync}")
    allowed_path = _prepare_allowed_path(path)
    entry = build_authorized_keys_entry(public_key, allowed_path, rrsync)
    marker = "offsync:" + hashlib.sha256(public_key.strip().encode("utf-8")).hexdigest()[:16]
    authorized_keys = Path.home() / ".ssh" / "authorized_keys"
    authorized_keys.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    authorized_keys.touch(mode=0o600, exist_ok=True)
    existing = authorized_keys.read_text(encoding="utf-8").splitlines()
    kept = [line for line in existing if marker not in line]
    kept.append(entry + f" {marker}")
    authorized_keys.write_text("\n".join(kept) + "\n", encoding="utf-8")
    authorized_keys.chmod(0o600)
    return allowed_path


def target_from_login(login: str, remote_path: str, rrsync: str = "/usr/bin/rrsync") -> Target:
    user, host = parse_login(login)
    validate_remote_path(remote_path)
    validate_rrsync_path(rrsync)
    return Target(login=login, user=user, host=host, remote_path=remote_path, rrsync=rrsync)


def suggested_controller_command(path: str, rrsync: str = "/usr/bin/rrsync") -> str:
    user = getpass.getuser()
    host = socket.getfqdn() or socket.gethostname()
    login = f"{user}@{host}"
    command = ["offsync", "target", "add", login, "--path", path]
    if rrsync != "/usr/bin/rrsync":
        command.extend(["--rrsync", rrsync])
    return " ".join(shlex.quote(part) for part in command)


def _prepare_allowed_path(path: str) -> str:
    if not path:
        raise OffsyncError("target path is required")
    expanded = Path(path).expanduser()
    expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
    expanded.chmod(0o700)
    resolved = str(expanded.resolve())
    validate_remote_path(resolved)
    return resolved
