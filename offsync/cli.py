from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import (
    add_or_update_target,
    config_path,
    default_config,
    key_path,
    load_config,
    public_key_path,
    save_config,
)
from .deps import check_dependencies, ensure_dependencies, install_dependencies
from .ssh import OffsyncError, ensure_keypair, ensure_known_host, verify_restricted_rsync
from .sync import apply_plan, build_plan
from .target import (
    controller_public_key_text,
    install_controller_key,
    suggested_controller_command,
    target_from_login,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="offsync",
        description="SSH-only deterministic file sync",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser(
        "init",
        help="create keypair and config",
        description="Create the controller config and dedicated offsync SSH keypair.",
    )
    init_parser.add_argument("--source", default=None, help="source directory to sync (default: current directory)")

    link_parser = subcommands.add_parser(
        "link",
        help="install a controller key on this target",
        description="Run on a target node to install the controller public key with strict file-transfer restrictions.",
    )
    link_parser.add_argument(
        "--path",
        default=".offsync/sync",
        help="directory this target allows the controller to sync into (default: ~/.offsync/sync)",
    )
    link_parser.add_argument(
        "--rrsync",
        default="/usr/bin/rrsync",
        help="absolute path to rrsync on this target (default: /usr/bin/rrsync)",
    )
    link_parser.add_argument("--key", default=None, help="controller public key text")
    link_parser.add_argument("--key-file", default=None, help="file containing the controller public key")

    target_parser = subcommands.add_parser("target", help="manage controller target config")
    target_subcommands = target_parser.add_subparsers(dest="target_command", required=True)
    target_add = target_subcommands.add_parser(
        "add",
        help="add a linked target to controller config",
        description="Verify host trust and restricted rsync access, then add a linked target to controller config.",
    )
    target_add.add_argument("login", help="remote target in user@host form")
    target_add.add_argument("--path", required=True, help="absolute target directory reported by offsync link")
    target_add.add_argument(
        "--rrsync",
        default="/usr/bin/rrsync",
        help="absolute path to rrsync on the target (default: /usr/bin/rrsync)",
    )

    deps_parser = subcommands.add_parser(
        "install-deps",
        help="install required system packages",
        description="Install ssh/rsync system dependencies using the detected package manager, after confirmation.",
    )
    deps_parser.add_argument(
        "--role",
        choices=["controller", "target", "both"],
        default="both",
        help="dependencies to install (default: both)",
    )
    deps_parser.add_argument("-y", "--yes", action="store_true", help="do not prompt before installing packages")

    subcommands.add_parser(
        "plan",
        help="print deterministic transfer plan",
        description="Scan the configured source and targets, then print added, modified, and target-only files.",
    )
    subcommands.add_parser(
        "apply",
        help="apply and verify the transfer plan",
        description="Transfer planned file changes with rsync over SSH, then verify the target state.",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return cmd_init(args.source)
        if args.command == "link":
            return cmd_link(args.path, args.rrsync, args.key, args.key_file)
        if args.command == "target" and args.target_command == "add":
            return cmd_target_add(args.login, args.path, args.rrsync)
        if args.command == "install-deps":
            return cmd_install_deps(args.role, args.yes)
        if args.command == "plan":
            return cmd_plan()
        if args.command == "apply":
            return cmd_apply()
    except OffsyncError as exc:
        print(f"offsync: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"offsync: {exc}", file=sys.stderr)
        return 1
    return 2


def cmd_init(source: str | None) -> int:
    ensure_dependencies("controller")
    ensure_keypair()
    path = config_path()
    if path.exists():
        config = load_config(path)
        if source is not None:
            config.source = default_config(source).source
            save_config(config, path)
    else:
        config = default_config(source)
        save_config(config, path)
    print(f"✓ initialized {path}")
    print(f"  source: {config.source}")
    print(f"  key: {key_path()}")
    print("  public key:")
    print(public_key_path().read_text(encoding="utf-8").strip())
    return 0


def cmd_link(path: str = ".offsync/sync", rrsync: str = "/usr/bin/rrsync", key: str | None = None, key_file: str | None = None) -> int:
    _ensure_target_dependencies(rrsync)
    public_key = _read_public_key_arg(key, key_file)
    print("→ installing key")
    allowed_path = install_controller_key(public_key, path, rrsync)
    print("✓ controller linked")
    print(f"  allowed path: {allowed_path}")
    print("  run on controller:")
    print(f"  {suggested_controller_command(allowed_path, rrsync)}")
    return 0


def cmd_target_add(login: str, remote_path: str, rrsync: str = "/usr/bin/rrsync") -> int:
    config = load_config()
    target = target_from_login(login, remote_path, rrsync)
    print("→ verifying host key")
    ensure_known_host(target.host)
    print("→ verifying restricted rsync access")
    verify_restricted_rsync(target)
    save_config(add_or_update_target(config, target))
    print(f"✓ {target.host} added")
    print(f"  target: {target.remote_path}")
    return 0


def cmd_install_deps(role: str, yes: bool) -> int:
    report = check_dependencies(role)
    if report.ok():
        print(f"✓ {role} dependencies already installed")
        return 0
    print("missing system dependencies: " + ", ".join(report.missing))
    install_dependencies(role, assume_yes=yes)
    report = check_dependencies(role)
    if not report.ok():
        raise OffsyncError("dependencies are still missing: " + ", ".join(report.missing))
    print(f"✓ {role} dependencies installed")
    return 0


def cmd_plan() -> int:
    config = load_config()
    plans = build_plan(config)
    for plan in plans:
        print(f"{plan.target.host}")
        _print_group("added", plan.added)
        _print_group("modified", plan.modified)
        _print_group("missing", plan.missing)
    if not plans:
        print("no targets linked")
    return 0


def cmd_apply() -> int:
    config = load_config()
    plans = apply_plan(config)
    for plan in plans:
        if plan.is_empty():
            print(f"✓ {plan.target.host} already in sync")
        else:
            print(f"✓ {plan.target.host} synced ({len(plan.added) + len(plan.modified)} files changed)")
    if not plans:
        print("no targets linked")
    return 0


def _print_group(name: str, values: list[str]) -> None:
    print(f"  {name}:")
    if not values:
        print("    - none")
        return
    for value in values:
        print(f"    - {value}")


def _read_public_key_arg(key: str | None, key_file: str | None) -> str:
    if key and key_file:
        raise OffsyncError("use only one of --key or --key-file")
    if key:
        return key.strip()
    if key_file:
        return Path(key_file).expanduser().read_text(encoding="utf-8").strip()
    return controller_public_key_text()


def _ensure_target_dependencies(rrsync: str) -> None:
    report = check_dependencies("target")
    missing = [
        command
        for command in report.missing
        if not (command == "rrsync" and Path(rrsync).expanduser().exists())
    ]
    if not missing:
        return
    if not sys.stdin.isatty():
        raise OffsyncError(
            "missing system dependencies: "
            + ", ".join(missing)
            + "; run `offsync install-deps --role target` first"
        )
    print("missing system dependencies: " + ", ".join(missing))
    try:
        answer = input("Install missing system packages now? [y/N] ")
    except EOFError as exc:
        raise OffsyncError("cannot prompt for dependency installation; run `offsync install-deps --role target` first") from exc
    if answer.lower() not in {"y", "yes"}:
        raise OffsyncError("missing required system dependencies")
    install_dependencies("target", assume_yes=True)
