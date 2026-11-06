"""Attribute-level diff of a resource change, with masking applied to every value shown."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .mask import MASK, UNKNOWN, _child, name_is_secret, redact, scrub_string

ABSENT = object()
MAX_DEPTH = 48
MAX_VALUE_CHARS = 200


@dataclass
class Entry:
    path: tuple[str | int, ...]
    op: str  # "+" "-" "~"
    before: str  # already masked and rendered; "" when op == "+"
    after: str

    @property
    def top(self) -> str:
        return str(self.path[0]) if self.path else ""


def fmt_path(path: tuple[str | int, ...]) -> str:
    out = ""
    for p in path:
        if isinstance(p, int):
            out += f"[{p}]"
        elif p.replace("_", "").replace("-", "").isalnum() and p[:1].isalpha() or p[:1] == "_":
            out += ("." if out else "") + p
        else:
            out += "[" + json.dumps(p, ensure_ascii=False) + "]"
    return out or "(value)"


def render(v: Any) -> str:
    """Compact JSON for a value that has ALREADY been redacted."""
    if v is UNKNOWN or v == UNKNOWN:
        return UNKNOWN
    if v == MASK:
        return MASK
    try:
        s = json.dumps(v, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError, RecursionError):
        s = "(unprintable value)"
    if len(s) > MAX_VALUE_CHARS:
        s = s[:MAX_VALUE_CHARS] + f"...(+{len(s) - MAX_VALUE_CHARS} chars)"
    return s


def _same(a: Any, b: Any) -> bool:
    return type(a) is type(b) and a == b


class _Walker:
    def __init__(self, limit: int) -> None:
        self.out: list[Entry] = []
        self.limit = limit
        self.truncated = False

    def add(self, path: tuple[str | int, ...], op: str, b: str, a: str) -> None:
        if len(self.out) >= self.limit:
            self.truncated = True
            return
        self.out.append(Entry(path, op, b, a))

    def walk(
        self,
        b: Any,
        a: Any,
        unk: Any,
        bs: Any,
        as_: Any,
        path: tuple[str | int, ...],
        sec_b: bool,
        sec_a: bool,
        depth: int,
    ) -> None:
        if self.truncated:
            return
        if unk is True:
            a = UNKNOWN
        elif a is ABSENT and isinstance(unk, (dict, list)) and unk:
            a = {} if isinstance(unk, dict) else []
        if b is None and a is not UNKNOWN and isinstance(a, (dict, list)) and a:
            b = ABSENT
        if a is None and isinstance(b, (dict, list)) and b and unk is not True:
            a = ABSENT
        if depth > MAX_DEPTH:
            self.add(path, "~", "(nested too deep)", "(nested too deep)")
            return
        mask_b = bs is True or (sec_b and b not in (None, ABSENT) and not isinstance(b, bool))
        mask_a = as_ is True or (sec_a and a not in (None, ABSENT, UNKNOWN) and not isinstance(a, bool))
        if not mask_b and not mask_a:
            if isinstance(b, dict) and isinstance(a, dict):
                self._dicts(b, a, unk, bs, as_, path, sec_b, sec_a, depth)
                return
            if isinstance(b, list) and isinstance(a, list):
                self._lists(b, a, unk, bs, as_, path, sec_b, sec_a, depth)
                return
            if b is ABSENT and isinstance(a, dict) and (a or unk):
                self._dicts({}, a, unk, bs, as_, path, sec_b, sec_a, depth)
                return
            if b is ABSENT and isinstance(a, list) and (a or unk):
                self._lists([], a, unk, bs, as_, path, sec_b, sec_a, depth)
                return
            if a is ABSENT and isinstance(b, dict) and b:
                self._dicts(b, {}, unk, bs, as_, path, sec_b, sec_a, depth)
                return
            if a is ABSENT and isinstance(b, list) and b:
                self._lists(b, [], unk, bs, as_, path, sec_b, sec_a, depth)
                return
        if a is UNKNOWN:
            bt = "" if b is ABSENT else self._show(b, bs, sec_b)
            self.add(path, "+" if b is ABSENT else "~", bt, UNKNOWN)
            return
        if b is ABSENT:
            self.add(path, "+", "", self._show(a, as_, sec_a))
            return
        if a is ABSENT:
            self.add(path, "-", self._show(b, bs, sec_b), "")
            return
        if (mask_b or mask_a) and _same(b, a):
            return  # equal, and we never show it
        if not (mask_b or mask_a) and _deep_same(b, a):
            return
        self.add(path, "~", self._show(b, bs, sec_b), self._show(a, as_, sec_a))

    @staticmethod
    def _show(v: Any, sens: Any, sec: bool) -> str:
        if v is ABSENT:
            return ""
        return render(redact(v, sens, sec))

    def _dicts(
        self,
        b: dict[str, Any],
        a: dict[str, Any],
        unk: Any,
        bs: Any,
        as_: Any,
        path: tuple[str | int, ...],
        sec_b: bool,
        sec_a: bool,
        depth: int,
    ) -> None:
        keys = list(b)
        keys += [k for k in a if k not in b]
        if isinstance(unk, dict):
            keys += [k for k in unk if k not in b and k not in a]
        if not keys and (b or a):
            return
        for k in keys:
            u = _child(unk, k)
            if u is False and k not in a and k not in b:
                continue
            nm = name_is_secret(k)
            self.walk(
                b.get(k, ABSENT),
                a.get(k, ABSENT),
                u,
                _child(bs, k),
                _child(as_, k),
                (*path, k),
                sec_b or nm,
                sec_a or nm,
                depth + 1,
            )

    def _lists(
        self,
        b: list[Any],
        a: list[Any],
        unk: Any,
        bs: Any,
        as_: Any,
        path: tuple[str | int, ...],
        sec_b: bool,
        sec_a: bool,
        depth: int,
    ) -> None:
        n = max(len(b), len(a), len(unk) if isinstance(unk, list) else 0)
        for i in range(n):
            self.walk(
                b[i] if i < len(b) else ABSENT,
                a[i] if i < len(a) else ABSENT,
                _child(unk, i),
                _child(bs, i),
                _child(as_, i),
                (*path, i),
                sec_b,
                sec_a,
                depth + 1,
            )


def _deep_same(a: Any, b: Any, depth: int = 0) -> bool:
    if depth > 200:
        return True
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_deep_same(a[k], b[k], depth + 1) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_deep_same(x, y, depth + 1) for x, y in zip(a, b, strict=True))
    return _same(a, b)


def diff_change(
    change: dict[str, Any], limit: int = 300, secret_name: bool = False
) -> tuple[list[Entry], bool]:
    """Diff change.before -> change.after. Returns (entries, truncated)."""
    w = _Walker(limit)
    before = change.get("before", ABSENT)
    after = change.get("after", ABSENT)
    actions = change.get("actions") or []
    if actions == ["create"] and before is None:
        before = ABSENT
    if "delete" in actions and "create" not in actions and after is None:
        after = ABSENT
    w.walk(
        before,
        after,
        change.get("after_unknown", False),
        change.get("before_sensitive", False),
        change.get("after_sensitive", False),
        (),
        secret_name,
        secret_name,
        0,
    )
    return w.out, w.truncated


def render_entry(e: Entry) -> str:
    p = fmt_path(e.path)
    if e.op == "+":
        return f"+ {p}: {e.after}"
    if e.op == "-":
        return f"- {p}: {e.before}"
    return f"~ {p}: {e.before} -> {e.after}"


def safe_text(s: str, limit: int = 300) -> str:
    """Scrub and bound a free-form string (addresses, reasons) before output."""
    s = scrub_string(s)
    return s if len(s) <= limit else s[:limit] + "..."


def fmt_replace_path(p: Any) -> str:
    """Format one replace_paths entry (a list of attribute names / indexes)."""
    if not isinstance(p, list):
        return "(unknown path)"
    return fmt_path(tuple(x if isinstance(x, (str, int)) else str(x) for x in p))
