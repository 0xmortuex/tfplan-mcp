"""Safe plan loading: sandbox, size cap, one efficient parse, shape validation."""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

DEFAULT_MAX_MB = 256
_CACHE_SIZE = 2


class PlanError(Exception):
    """A problem the caller can act on (bad path, not a plan, too big, ...)."""


def real(path: str) -> str:
    """The one place paths are resolved: converts every resolution failure to PlanError."""
    try:
        return os.path.realpath(os.path.expanduser(path))
    except (OSError, ValueError) as e:
        raise PlanError(f"cannot resolve path ({type(e).__name__}: {str(e)[:120]})") from e


@dataclass
class Settings:
    root: str = ""
    max_bytes: int = DEFAULT_MAX_MB * 1024 * 1024

    def __post_init__(self) -> None:
        if not self.root:
            self.root = real(os.getcwd())


settings = Settings()


def configure(root: str | None, max_mb: float | None) -> None:
    if root is not None:
        r = real(root)
        if not os.path.isdir(r):
            raise PlanError(f"--dir {root!r} is not a directory")
        settings.root = r
    if max_mb is not None:
        if max_mb <= 0:
            raise PlanError("--max-mb must be positive")
        settings.max_bytes = int(max_mb * 1024 * 1024)
    _cache.clear()


def resolve(path: str) -> str:
    """Resolve path against the sandbox root and refuse anything outside it."""
    if not isinstance(path, str) or not path.strip():
        raise PlanError("path is empty - pass the path of a plan JSON file")
    if "\x00" in path:
        raise PlanError("path contains a NUL character")
    expanded = os.path.expanduser(path)
    joined = expanded if os.path.isabs(expanded) else os.path.join(settings.root, expanded)
    full = real(joined)
    root_n, full_n = os.path.normcase(settings.root), os.path.normcase(full)
    try:
        inside = os.path.commonpath([root_n, full_n]) == root_n
    except ValueError:  # different drives on Windows
        inside = False
    if not inside:
        raise PlanError(
            f"path is outside the allowed directory {settings.root!r} "
            "(the server was started with --dir; copy the plan inside it)"
        )
    return full


@dataclass
class Change:
    rc: dict[str, Any]
    address: str
    deposed: str
    type: str
    module: str
    kind: str  # create update delete replace read no-op forget other
    order: str  # "" | "delete_then_create" | "create_then_delete"
    actions: list[str]
    moved_from: str
    importing: bool
    reason: str
    change: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.address + (f" (deposed {self.deposed})" if self.deposed else "")

    @property
    def label(self) -> str:
        if self.kind == "no-op":
            extra = []
            if self.importing:
                extra.append("import")
            if self.moved_from:
                extra.append("move")
            if extra:
                return "no-op (" + "+".join(extra) + ")"
        return self.kind


def classify(actions: list[str]) -> tuple[str, str]:
    if actions == ["delete", "create"]:
        return "replace", "delete_then_create"
    if actions == ["create", "delete"]:
        return "replace", "create_then_delete"
    if len(actions) == 1 and actions[0] in ("create", "update", "delete", "read", "no-op", "forget"):
        return actions[0], ""
    return "other", ""


def make_change(rc: Any) -> Change | None:
    if not isinstance(rc, dict) or not isinstance(rc.get("address"), str):
        return None
    ch = rc.get("change")
    if not isinstance(ch, dict):
        return None
    acts = ch.get("actions")
    if not isinstance(acts, list) or not all(isinstance(a, str) for a in acts):
        return None
    kind, order = classify(acts)
    mod = rc.get("module_address")
    return Change(
        rc=rc,
        address=rc["address"],
        deposed=str(rc.get("deposed") or ""),
        type=str(rc.get("type") or ""),
        module=mod if isinstance(mod, str) and mod else "root",
        kind=kind,
        order=order,
        actions=acts,
        moved_from=str(rc.get("previous_address") or ""),
        importing=bool(ch.get("importing")),
        reason=str(rc.get("action_reason") or ""),
        change=ch,
    )


@dataclass
class Plan:
    path: str
    size: int
    raw: dict[str, Any]
    changes: list[Change]
    drift: list[Change]
    malformed: int

    def find(self, address: str) -> list[Change]:
        return [c for c in self.changes if c.address == address]


def _bad_constant(name: str) -> Any:
    raise ValueError(f"the file contains the non-JSON constant {name}")


def _parse_int(s: str) -> Any:
    if len(s) > 1000:
        return f"(huge integer, {len(s)} digits)"
    return int(s)


def parse_bytes(data: bytes) -> Any:
    if data[:4] == b"PK\x03\x04":
        raise PlanError(
            "this is a binary plan file (a zip archive). Convert it first: "
            "terraform show -json tfplan > plan.json (or: tofu show -json tfplan)"
        )
    try:
        return json.loads(data, parse_constant=_bad_constant, parse_int=_parse_int)
    except RecursionError as e:
        raise PlanError("JSON is nested too deeply to parse safely") from e
    except UnicodeDecodeError as e:
        raise PlanError("file is not UTF-8 text (is it a binary plan? use terraform show -json)") from e
    except json.JSONDecodeError as e:
        head = data[:400]
        if b'"@level"' in head or b'"type":"version"' in head or b'"@message"' in head:
            raise PlanError(
                "this looks like the streaming UI log from `terraform plan -json` (one JSON "
                "object per line), not a plan. Save the plan with `terraform plan -out=tfplan` "
                "and then run `terraform show -json tfplan > plan.json`"
            ) from e
        raise PlanError(f"not valid JSON: {e.msg} at line {e.lineno} column {e.colno}") from e
    except ValueError as e:
        raise PlanError(f"cannot parse the file: {str(e)[:200]}") from e


def validate(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise PlanError("the JSON top level is not an object, so this is not a plan")
    plan_keys = ("resource_changes", "planned_values", "configuration", "output_changes", "prior_state")
    has_plan = any(k in obj for k in plan_keys)
    if "values" in obj and not has_plan:
        raise PlanError(
            "this is a STATE (terraform show -json of a state file: it has `values` but no "
            "`resource_changes`/`planned_values`), not a plan. Produce a plan with "
            "`terraform plan -out=tfplan` then `terraform show -json tfplan`"
        )
    if obj.get("version") == 4 and "resources" in obj and not has_plan:
        raise PlanError("this is a raw terraform.tfstate file, not a plan JSON")
    fv = obj.get("format_version")
    if not has_plan or not isinstance(fv, str):
        raise PlanError(
            "this JSON is not a Terraform plan: expected `format_version` plus plan keys such as "
            "`resource_changes`. Create it with: terraform show -json tfplan > plan.json"
        )
    if fv.split(".")[0] != "1":
        raise PlanError(f"unsupported plan format_version {fv!r} (this tool understands 1.x)")
    return obj


def as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


_cache: OrderedDict[tuple[str, int, int], Plan] = OrderedDict()


def load(path: str) -> Plan:
    full = resolve(path)
    try:
        st = os.stat(full)
    except FileNotFoundError:
        raise PlanError(f"file not found: {path}") from None
    except (OSError, ValueError) as e:
        raise PlanError(f"cannot read the path ({getattr(e, 'strerror', None) or type(e).__name__})") from e
    if not os.path.isfile(full):
        raise PlanError(f"not a file: {path}")
    if st.st_size > settings.max_bytes:
        raise PlanError(
            f"plan file is {st.st_size / 1048576:.1f} MB, over the {settings.max_bytes / 1048576:.0f} MB "
            "limit. Restart the server with --max-mb N (parsing needs several times the file size "
            "in RAM) or trim the plan"
        )
    ck = (full, st.st_mtime_ns, st.st_size)
    hit = _cache.get(ck)
    if hit is not None:
        _cache.move_to_end(ck)
        return hit
    try:
        with open(full, "rb") as f:
            data = f.read(settings.max_bytes + 1)
    except (OSError, ValueError) as e:
        raise PlanError(f"cannot read the path ({getattr(e, 'strerror', None) or type(e).__name__})") from e
    if len(data) > settings.max_bytes:
        raise PlanError("plan file grew past the size limit while reading")
    raw = validate(parse_bytes(data))
    del data
    changes: list[Change] = []
    drift: list[Change] = []
    bad = 0
    for src, dst in ((raw.get("resource_changes"), changes), (raw.get("resource_drift"), drift)):
        for rc in as_list(src):
            c = make_change(rc)
            if c is None:
                bad += 1
            else:
                dst.append(c)
    plan = Plan(full, st.st_size, raw, changes, drift, bad)
    _cache[ck] = plan
    while len(_cache) > _CACHE_SIZE:
        _cache.popitem(last=False)
    return plan
