from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shutil
import sys
import shlex
import socket
import subprocess
import tempfile
from pathlib import Path

from .config import Target, key_path, public_key_path


class OffsyncError(RuntimeError):
    pass


ALLOWED_PUBLIC_KEY_TYPES = {
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
}


def parse_login(login: str) -> tuple[str, str]:
    if "@" not in login:
        raise OffsyncError("target must be in user@host form")
    user, host = login.split("@", 1)
    if not user or not host:
        raise OffsyncError("target must be in user@host form")
    if any(char in login for char in "\r\n\t "):
        raise OffsyncError("target must not contain whitespace")
    if not _is_safe_login_part(user):
        raise OffsyncError("target user may only contain letters, numbers, '.', '_', and '-'")
    if host.startswith("-") or not _is_safe_host(host):
        raise OffsyncError("target host may only contain letters, numbers, '.', and '-'")
    return user, host


def ensure_keypair() -> None:
    private = key_path()
    public = public_key_path()
    private.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if private.exists() and public.exists():
        private.chmod(0o600)
        return
    if private.exists() != public.exists():
        raise OffsyncError(f"incomplete keypair at {private}; remove it and rerun init")
    comment = f"offsync@{socket.gethostname()}"
    run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(private),
            "-N",
            "",
            "-C",
            comment,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    private.chmod(0o600)
    public.chmod(0o644)


def build_authorized_keys_entry(public_key: str, remote_path: str, rrsync: str = "/usr/bin/rrsync") -> str:
    validate_remote_path(remote_path)
    validate_rrsync_path(rrsync)
    public_key = validate_public_key(public_key)
    forced_command = f'{rrsync} -wo {shlex.quote(remote_path)}'
    escaped_command = forced_command.replace("\\", "\\\\").replace('"', '\\"')
    options = [
        f'command="{escaped_command}"',
        "no-port-forwarding",
        "no-agent-forwarding",
        "no-X11-forwarding",
        "no-pty",
    ]
    return ",".join(options) + " " + public_key


def validate_public_key(public_key: str) -> str:
    public_key = public_key.strip()
    if "\n" in public_key or "\r" in public_key:
        raise OffsyncError("public key must be a single line")
    parts = public_key.split()
    if len(parts) < 2:
        raise OffsyncError("public key must include key type and key data")
    key_type, key_data = parts[0], parts[1]
    if key_type not in ALLOWED_PUBLIC_KEY_TYPES:
        raise OffsyncError(f"unsupported public key type: {key_type}")
    try:
        base64.b64decode(key_data.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise OffsyncError("public key data is not valid base64") from exc
    return public_key


def validate_remote_path(remote_path: str) -> None:
    if not remote_path.startswith("/"):
        raise OffsyncError("remote path must be absolute")
    if any(char in remote_path for char in "\r\n\0"):
        raise OffsyncError("remote path must not contain control characters")
    parts = [part for part in remote_path.split("/") if part]
    if any(part == ".." for part in parts):
        raise OffsyncError("remote path must not contain '..'")


def validate_rrsync_path(rrsync: str) -> None:
    if not rrsync.startswith("/") or any(char in rrsync for char in "\r\n\"\0"):
        raise OffsyncError("rrsync path must be absolute and must not contain quotes or control characters")
    if any(part == ".." for part in rrsync.split("/") if part):
        raise OffsyncError("rrsync path must not contain '..'")


def ensure_known_host(host: str) -> None:
    probe = run(["ssh-keygen", "-F", host], capture_output=True, text=True, check=False)
    if probe.returncode == 0:
        return
    if not sys.stdin.isatty():
        raise OffsyncError(f"unknown host key for {host}; run `offsync target add` interactively once")

    print(f"→ fetching host key for {host}")
    scan = run(["ssh-keyscan", "-T", "5", host], capture_output=True, text=True, check=False)
    if scan.returncode != 0 or not scan.stdout.strip():
        raise OffsyncError(f"could not fetch host key for {host}")
    fingerprint = known_hosts_fingerprint(scan.stdout)
    print(f"host key fingerprint: {fingerprint}")
    try:
        answer = input(f"Trust this host key for {host}? Type 'yes' to continue: ")
    except EOFError as exc:
        raise OffsyncError(f"could not confirm host key trust for {host}") from exc
    if answer != "yes":
        raise OffsyncError("host key was not trusted")

    known_hosts = Path.home() / ".ssh" / "known_hosts"
    known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with known_hosts.open("a", encoding="utf-8") as handle:
        handle.write(scan.stdout)
        if not scan.stdout.endswith("\n"):
            handle.write("\n")
    known_hosts.chmod(0o600)


def known_hosts_fingerprint(known_hosts_text: str) -> str:
    first = next((line for line in known_hosts_text.splitlines() if line and not line.startswith("#")), "")
    parts = first.split()
    if len(parts) < 3:
        raise OffsyncError("invalid host key returned by ssh-keyscan")
    try:
        blob = base64.b64decode(parts[2].encode("ascii"))
    except ValueError as exc:
        raise OffsyncError("invalid host key returned by ssh-keyscan") from exc
    digest = base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")
    return f"SHA256:{digest}"


def verify_restricted_rsync(target: Target) -> None:
    with tempfile.TemporaryDirectory(prefix="offsync-verify-") as tmp:
        cmd = rsync_base(target.login) + [
            "--dry-run",
            "--checksum",
            "-v",
            f"{tmp}/",
            f"{target.login}:.",
        ]
        run(cmd, capture_output=True, text=True, check=True)


def rsync_base(login: str) -> list[str]:
    ssh_cmd = " ".join(
        shlex.quote(part)
        for part in [
            "ssh",
            "-i",
            str(key_path()),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
        ]
    )
    return [rsync_path(), "-e", ssh_cmd]


def rsync_path() -> str:
    override = os.environ.get("OFFSYNC_RSYNC")
    if override:
        if not Path(override).expanduser().exists():
            raise OffsyncError(f"OFFSYNC_RSYNC does not exist: {override}")
        return str(Path(override).expanduser())

    candidates = [
        shutil.which("rsync"),
        "/opt/homebrew/bin/rsync",
        "/usr/local/bin/rsync",
    ]
    for candidate in candidates:
        if candidate and _is_gnu_rsync(candidate):
            return candidate

    raise OffsyncError(
        "GNU rsync is required on the controller for rrsync compatibility. "
        "Install it with `brew install rsync` or set OFFSYNC_RSYNC to a GNU rsync binary."
    )


def _is_safe_login_part(value: str) -> bool:
    return all(char.isalnum() or char in "._-" for char in value)


def _is_safe_host(value: str) -> bool:
    return all(char.isalnum() or char in ".-" for char in value)


def _is_gnu_rsync(path: str) -> bool:
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return False
    output = result.stdout + result.stderr
    return result.returncode == 0 and "openrsync" not in output.lower() and "rsync  version" in output.lower()


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, **kwargs)
    except FileNotFoundError as exc:
        raise OffsyncError(f"required command not found: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        cmd = " ".join(shlex.quote(part) for part in args)
        stderr = ""
        if getattr(exc, "stderr", None):
            stderr = f": {exc.stderr.strip()}"
        raise OffsyncError(f"command failed: {cmd}{stderr}") from exc
