from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .audit import log_operation
from .config import Config, Target
from .ssh import OffsyncError, rsync_base, run


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str


@dataclass
class TargetPlan:
    target: Target
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def changes(self) -> list[str]:
        return sorted(set(self.added + self.modified + self.missing))

    def is_empty(self) -> bool:
        return not self.added and not self.modified and not self.missing


def build_plan(config: Config) -> list[TargetPlan]:
    source = validate_source(config.source)
    plans: list[TargetPlan] = []
    for target in sorted(config.targets, key=lambda item: item.login):
        output = rsync_dry_run(source, target, config, include_delete_scan=True)
        changes = parse_rsync_itemize(output)
        plan = TargetPlan(target=target)
        for change in changes:
            if change.status == "added":
                plan.added.append(change.path)
            elif change.status == "modified":
                plan.modified.append(change.path)
            elif change.status == "missing":
                plan.missing.append(change.path)
        plan.added.sort()
        plan.modified.sort()
        plan.missing.sort()
        plans.append(plan)
    return plans


def apply_plan(config: Config) -> list[TargetPlan]:
    source = validate_source(config.source)
    plans = build_plan(config)
    for plan in plans:
        if plan.missing:
            raise OffsyncError(
                f"{plan.target.host} has target-only files; refusing hidden delete: "
                + ", ".join(plan.missing[:10])
            )
        if plan.is_empty():
            log_operation(plan.target.host, "apply", [])
            continue
        changed = plan.added + plan.modified
        rsync_apply(source, plan.target, config)
        verify_target(source, plan.target, config)
        log_operation(plan.target.host, "apply", changed)
    return plans


def verify_target(source: Path, target: Target, config: Config) -> None:
    if config.verify != "hash":
        raise OffsyncError("only verify: hash is supported")
    output = rsync_dry_run(source, target, config)
    changes = parse_rsync_itemize(output)
    pending = [change.path for change in changes if change.status in {"added", "modified"}]
    if pending:
        raise OffsyncError(f"verification failed for {target.host}: {', '.join(sorted(pending))}")


def validate_source(source: str) -> Path:
    path = Path(source).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        raise OffsyncError(f"source directory does not exist: {path}")
    return path


def local_manifest(source: Path) -> list[str]:
    files: list[str] = []
    for root, dirnames, filenames in os.walk(source, followlinks=False):
        root_path = Path(root)
        dirnames[:] = sorted(
            dirname for dirname in dirnames if _safe_local_path(source, root_path / dirname, is_dir=True)
        )
        for filename in sorted(filenames):
            path = root_path / filename
            if _safe_local_path(source, path, is_dir=False):
                files.append(path.relative_to(source).as_posix())
    return files


def parse_rsync_itemize(output: str) -> list[FileChange]:
    changes: list[FileChange] = []
    for raw in output.splitlines():
        line = raw.rstrip("\n")
        if not line or line.startswith("sending ") or line.startswith("sent "):
            continue
        if line.startswith("*deleting"):
            changes.append(FileChange(path=line.removeprefix("*deleting").strip(), status="missing"))
            continue
        if len(line) < 13 or line[11] != " ":
            continue
        code = line[:11]
        path = line[12:]
        if not path or path.endswith("/"):
            continue
        if "+++++++++" in code:
            status = "added"
        elif code[0] == ">" or code[2] in {"c", "s", "t"}:
            status = "modified"
        else:
            continue
        changes.append(FileChange(path=path, status=status))
    return sorted(changes, key=lambda item: (item.path, item.status))


def rsync_dry_run(source: Path, target: Target, config: Config, include_delete_scan: bool = False) -> str:
    args = _rsync_common(config) + [
        "--dry-run",
        "--itemize-changes",
    ]
    if include_delete_scan:
        args.append("--delete")
    args.extend([f"{source}/", f"{target.login}:{target.remote_path}/"])
    result = run(args, capture_output=True, text=True, check=True)
    return result.stdout


def rsync_apply(source: Path, target: Target, config: Config) -> None:
    args = _rsync_common(config) + [
        f"{source}/",
        f"{target.login}:{target.remote_path}/",
    ]
    run(args, check=True)


def _rsync_common(config: Config) -> list[str]:
    if config.delete:
        raise OffsyncError("delete: true is not implemented; refusing hidden deletes")
    if not config.overwrite:
        raise OffsyncError("overwrite: false is not implemented; refusing ambiguous merge behavior")
    if config.verify != "hash":
        raise OffsyncError("only verify: hash is supported")
    return [
        *rsync_base(""),
        "-a",
        "--checksum",
        "--safe-links",
        "--human-readable",
        "--out-format=%i %n",
        "--exclude=.git/",
    ]


def _safe_local_path(source: Path, path: Path, is_dir: bool) -> bool:
    try:
        resolved_parent = path.parent.resolve()
        resolved_parent.relative_to(source)
    except ValueError:
        raise OffsyncError(f"path escapes source scope: {path}")
    if path.is_symlink():
        target = path.resolve()
        try:
            target.relative_to(source)
        except ValueError as exc:
            raise OffsyncError(f"symlink escapes source scope: {path}") from exc
    if is_dir:
        return True
    if not path.is_file():
        return False
    return True


def manifest_hash(source: Path) -> str:
    digest = hashlib.sha256()
    for relpath in local_manifest(source):
        digest.update(relpath.encode("utf-8"))
        digest.update(b"\0")
        digest.update((source / relpath).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
