from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from .ssh import OffsyncError, rsync_path


@dataclass(frozen=True)
class DependencyReport:
    role: str
    missing: list[str]

    def ok(self) -> bool:
        return not self.missing


ROLE_COMMANDS = {
    "controller": ["ssh", "ssh-keygen", "ssh-keyscan", "rsync"],
    "target": ["rsync", "rrsync"],
    "both": ["ssh", "ssh-keygen", "ssh-keyscan", "rsync", "rrsync"],
}


def check_dependencies(role: str) -> DependencyReport:
    commands = ROLE_COMMANDS.get(role)
    if commands is None:
        raise OffsyncError(f"unknown dependency role: {role}")
    missing = [command for command in commands if shutil.which(command) is None]
    if role in {"controller", "both"} and "rsync" not in missing:
        try:
            rsync_path()
        except OffsyncError:
            missing.append("GNU rsync")
    return DependencyReport(role=role, missing=missing)


def ensure_dependencies(role: str, ask: bool = True) -> None:
    report = check_dependencies(role)
    if report.ok():
        return
    if not ask:
        raise OffsyncError("install missing dependencies with `offsync install-deps`")
    if not sys.stdin.isatty():
        raise OffsyncError(
            "missing system dependencies: "
            + ", ".join(report.missing)
            + "; run `offsync install-deps` first"
        )
    print("missing system dependencies: " + ", ".join(report.missing))
    if not _confirm("Install missing system packages now? [y/N] "):
        raise OffsyncError("missing required system dependencies")
    install_dependencies(role, assume_yes=True)


def install_dependencies(role: str, assume_yes: bool = False) -> None:
    if role not in ROLE_COMMANDS:
        raise OffsyncError(f"unknown dependency role: {role}")
    manager = _detect_package_manager()
    if manager is None:
        raise OffsyncError("could not detect a supported package manager")
    commands = _install_commands(manager, role)
    if not assume_yes:
        packages = _packages_for(manager, role)
        if not _confirm(f"Install system packages with {manager}: {', '.join(packages)}? [y/N] "):
            raise OffsyncError("dependency installation cancelled")
    for command in commands:
        _run(command)


def _detect_package_manager() -> str | None:
    for manager in ("apt-get", "dnf", "yum", "pacman", "zypper", "apk", "brew"):
        if shutil.which(manager):
            return manager
    return None


def _packages_for(manager: str, role: str) -> list[str]:
    if manager == "brew":
        package_map = {
            "controller": ["openssh", "rsync"],
            "target": ["rsync"],
            "both": ["openssh", "rsync"],
        }
    elif manager in {"dnf", "yum"}:
        package_map = {
            "controller": ["openssh-clients", "rsync"],
            "target": ["rsync"],
            "both": ["openssh-clients", "rsync"],
        }
    elif manager == "apk":
        package_map = {
            "controller": ["openssh-client", "rsync"],
            "target": ["rsync"],
            "both": ["openssh-client", "rsync"],
        }
    else:
        package_map = {
            "controller": ["openssh-client", "rsync"],
            "target": ["rsync"],
            "both": ["openssh-client", "rsync"],
        }
    return package_map[role]


def _install_commands(manager: str, role: str) -> list[list[str]]:
    packages = _packages_for(manager, role)
    if manager == "apt-get":
        return [_sudo(["apt-get", "update"]), _sudo(["apt-get", "install", "-y", *packages])]
    if manager in {"dnf", "yum"}:
        return [_sudo([manager, "install", "-y", *packages])]
    if manager == "pacman":
        return [_sudo(["pacman", "-Sy", "--needed", "--noconfirm", *packages])]
    if manager == "zypper":
        return [_sudo(["zypper", "install", "-y", *packages])]
    if manager == "apk":
        return [_sudo(["apk", "add", *packages])]
    if manager == "brew":
        return [["brew", "install", *packages]]
    raise OffsyncError(f"unsupported package manager: {manager}")


def _sudo(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    if shutil.which("sudo") is None:
        raise OffsyncError("sudo is required to install system packages")
    return ["sudo", *command]


def _run(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise OffsyncError(f"required command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise OffsyncError(f"dependency install command failed: {' '.join(command)}") from exc


def _confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        raise OffsyncError("cannot prompt for dependency installation; run `offsync install-deps` first")
    try:
        answer = input(prompt)
    except EOFError as exc:
        raise OffsyncError("cannot prompt for dependency installation; run `offsync install-deps` first") from exc
    return answer.lower() in {"y", "yes"}
