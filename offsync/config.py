from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CONFIG_NAME = "config.yaml"
KEY_NAME = "id_ed25519"


@dataclass(frozen=True)
class Target:
    login: str
    user: str
    host: str
    remote_path: str
    rrsync: str = "/usr/bin/rrsync"


@dataclass
class Config:
    source: str
    delete: bool = False
    overwrite: bool = True
    verify: str = "hash"
    targets: list[Target] = field(default_factory=list)
    version: int = 1


def offsync_home() -> Path:
    override = os.environ.get("OFFSYNC_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".offsync"


def config_path() -> Path:
    return offsync_home() / CONFIG_NAME


def key_path() -> Path:
    return offsync_home() / KEY_NAME


def public_key_path() -> Path:
    return key_path().with_suffix(".pub")


def default_config(source: str | None = None) -> Config:
    return Config(source=str(Path(source or os.getcwd()).expanduser().resolve()))


def load_config(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists():
        raise FileNotFoundError(f"missing config: {path}. Run `offsync init` first.")
    data = _parse_yaml_subset(path.read_text(encoding="utf-8"))
    targets = [
        Target(
            login=str(item["login"]),
            user=str(item["user"]),
            host=str(item["host"]),
            remote_path=str(item["remote_path"]),
            rrsync=str(item.get("rrsync", "/usr/bin/rrsync")),
        )
        for item in data.get("targets", [])
    ]
    return Config(
        version=int(data.get("version", 1)),
        source=str(data["source"]),
        delete=bool(data.get("delete", False)),
        overwrite=bool(data.get("overwrite", True)),
        verify=str(data.get("verify", "hash")),
        targets=targets,
    )


def save_config(config: Config, path: Path | None = None) -> None:
    path = path or config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(_render_yaml(config), encoding="utf-8")
    path.chmod(0o600)


def add_or_update_target(config: Config, target: Target) -> Config:
    kept = [existing for existing in config.targets if existing.login != target.login]
    kept.append(target)
    kept.sort(key=lambda item: item.login)
    config.targets = kept
    return config


def _render_yaml(config: Config) -> str:
    lines = [
        f"version: {config.version}",
        f"source: {_yaml_string(config.source)}",
        f"delete: {_yaml_bool(config.delete)}",
        f"overwrite: {_yaml_bool(config.overwrite)}",
        f"verify: {_yaml_string(config.verify)}",
        "targets:",
    ]
    for target in sorted(config.targets, key=lambda item: item.login):
        lines.extend(
            [
                f"  - login: {_yaml_string(target.login)}",
                f"    user: {_yaml_string(target.user)}",
                f"    host: {_yaml_string(target.host)}",
                f"    remote_path: {_yaml_string(target.remote_path)}",
                f"    rrsync: {_yaml_string(target.rrsync)}",
            ]
        )
    return "\n".join(lines) + "\n"


def _yaml_string(value: str) -> str:
    return json.dumps(value)


def _yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def _parse_yaml_subset(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    targets: list[dict[str, Any]] = []
    current_target: dict[str, Any] | None = None
    in_targets = False

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()

        if indent == 0:
            current_target = None
            if line == "targets:":
                in_targets = True
                result["targets"] = targets
                continue
            in_targets = False
            key, value = _split_key_value(line)
            result[key] = _parse_scalar(value)
            continue

        if in_targets and indent == 2 and line.startswith("- "):
            current_target = {}
            targets.append(current_target)
            rest = line[2:].strip()
            if rest:
                key, value = _split_key_value(rest)
                current_target[key] = _parse_scalar(value)
            continue

        if in_targets and indent == 4 and current_target is not None:
            key, value = _split_key_value(line)
            current_target[key] = _parse_scalar(value)
            continue

        raise ValueError(f"unsupported config line: {raw!r}")

    result.setdefault("targets", targets)
    return result


def _split_key_value(line: str) -> tuple[str, str]:
    if ":" not in line:
        raise ValueError(f"expected key/value line: {line!r}")
    key, value = line.split(":", 1)
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> Any:
    if value == "true":
        return True
    if value == "false":
        return False
    if value == "[]":
        return []
    if value.startswith('"'):
        return json.loads(value)
    try:
        return int(value)
    except ValueError:
        return value
