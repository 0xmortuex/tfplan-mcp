"""The seven analyses behind the tools. Each returns plain text for the agent."""

from __future__ import annotations

import difflib
import json
import re
from collections import Counter, defaultdict
from typing import Any

from .diff import diff_change, fmt_path, fmt_replace_path, render_entry, safe_text
from .loader import Change, Plan, PlanError, as_list
from .mask import MASK, UNKNOWN, name_is_secret, redact
from .risk import SCORE, SEVERITIES, assess

MAX_OUT_CHARS = 60_000
KINDS = ["create", "update", "replace", "delete", "read", "forget", "no-op", "other"]


def clip(text: str) -> str:
    if len(text) <= MAX_OUT_CHARS:
        return text
    return text[:MAX_OUT_CHARS] + f"\n... output truncated at {MAX_OUT_CHARS} characters; narrow the query."


def addr(s: str) -> str:
    return safe_text(s, 500)


def _glob(pattern: str) -> re.Pattern[str]:
    # fnmatch treats [] as a character class, which clashes with resource indexes. Only * and ? are wild.
    return re.compile("".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern), re.DOTALL)


# ------------------------------------------------------------------ plan_summary

def plan_summary(plan: Plan) -> str:
    raw = plan.raw
    warnings: list[str] = []
    by_kind = Counter(c.label if c.kind == "no-op" else c.kind for c in plan.changes)
    real = [c for c in plan.changes if c.kind != "no-op"]
    moved = sum(1 for c in plan.changes if c.moved_from)
    imported = sum(1 for c in plan.changes if c.importing)
    lines = [
        f"Plan file: {plan.size / 1048576:.2f} MB; format_version {raw.get('format_version')}; "
        f"terraform_version {safe_text(str(raw.get('terraform_version', 'unknown')), 40)}"
        + (f"; timestamp {safe_text(str(raw['timestamp']), 40)}" if raw.get("timestamp") else ""),
    ]
    counts = ", ".join(f"{k} {by_kind[k]}" for k in KINDS if k != "no-op" and by_kind.get(k)) or "none"
    noop_all = sum(v for k, v in by_kind.items() if k.startswith("no-op"))
    lines.append(f"Resource changes: {len(real)} real change(s) [{counts}]; {noop_all} no-op entries "
                 f"(moved {moved}, imported {imported}).")
    if not real and not moved and not imported:
        lines.append("This is an EMPTY plan: no resource will be created, changed or destroyed.")
    elif real and all(c.kind == "delete" for c in real):
        lines.append("DESTROY PLAN: every change is a delete; applying this removes everything listed.")
    by_type: dict[str, Counter[str]] = defaultdict(Counter)
    by_mod: dict[str, Counter[str]] = defaultdict(Counter)
    for c in real:
        by_type[c.type or "(unknown type)"][c.kind] += 1
        by_mod[c.module][c.kind] += 1
    if by_type:
        lines.append("By resource type:")
        for t, cnt in sorted(by_type.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))[:40]:
            lines.append(f"  {safe_text(t, 100)}: " + ", ".join(f"{k} {v}" for k, v in cnt.items()))
        if len(by_type) > 40:
            lines.append(f"  ... {len(by_type) - 40} more types")
        lines.append("By module:")
        for m, cnt in sorted(by_mod.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))[:40]:
            lines.append(f"  {addr(m)}: " + ", ".join(f"{k} {v}" for k, v in cnt.items()))
        if len(by_mod) > 40:
            lines.append(f"  ... {len(by_mod) - 40} more modules")
    lines.append(f"Drift: {len(plan.drift)} resource(s) changed outside Terraform"
                 + (" (see outputs_and_drift)" if plan.drift else "") + ".")
    oc = raw.get("output_changes")
    if isinstance(oc, dict) and oc:
        oc_kinds = Counter("/".join(v.get("actions", [])) if isinstance(v, dict) else "?" for v in oc.values())
        lines.append(f"Output changes: {len(oc)} (" + ", ".join(f"{k} {v}" for k, v in oc_kinds.items()) + ").")
    else:
        lines.append("Output changes: none.")
    checks = as_list(raw.get("checks"))
    if checks:
        st = Counter(str(c.get("status")) for c in checks if isinstance(c, dict))
        lines.append("Checks: " + ", ".join(f"{k} {v}" for k, v in st.items()) + ".")
        if st.get("fail"):
            warnings.append(f"{st['fail']} check block(s) are failing in this plan")
    # warnings
    if raw.get("errored") is True:
        warnings.append("the plan ERRORED: resource_changes may be partial and the plan cannot be applied")
    if raw.get("applyable") is False:
        warnings.append("plan is marked applyable=false")
    if raw.get("complete") is False:
        warnings.append("plan is marked complete=false: some changes are deferred to a later plan")
    deferred = as_list(raw.get("deferred_changes"))
    if deferred:
        warnings.append(f"{len(deferred)} change(s) are DEFERRED (not decided in this plan, e.g. unknown for_each)")
    if plan.malformed:
        warnings.append(f"{plan.malformed} resource_changes/resource_drift entries were malformed and skipped")
    if by_kind.get("other"):
        warnings.append(f"{by_kind['other']} change(s) have an action combination this tool does not recognise")
    if by_kind.get("forget"):
        warnings.append("some resources will be forgotten (removed from state, not destroyed)")
    if "resource_changes" not in raw and "planned_values" not in raw:
        warnings.append("plan has neither resource_changes nor planned_values")
    if warnings:
        lines.append("Warnings:")
        lines += [f"  - {w}" for w in warnings]
    return clip("\n".join(lines))


# ------------------------------------------------------------------ risky_changes

def risky_changes(plan: Plan, min_severity: str = "low", limit: int = 30) -> str:
    if min_severity not in SEVERITIES:
        raise PlanError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    limit = max(1, min(limit, 500))
    found = []
    for c in plan.changes:
        a = assess(c)
        if a is not None and SCORE[a.severity] >= SCORE[min_severity]:
            found.append(a)
    found.sort(key=lambda a: (-SCORE[a.severity], a.change.address))
    sev_counts = Counter(a.severity for a in found)
    head = "Risk review: " + (", ".join(f"{s} {sev_counts[s]}" for s in reversed(SEVERITIES) if sev_counts[s]) or "no findings")
    head += f" (min_severity={min_severity}; heuristics, not a substitute for reading the diff)."
    out = [head]
    for i, a in enumerate(found[:limit], 1):
        c = a.change
        out.append(f"{i}. [{a.severity.upper()}] {addr(c.key)}  action={'+'.join(c.actions)}")
        for r in a.reasons:
            out.append(f"     - {safe_text(r, 400)}")
    if len(found) > limit:
        out.append(f"... {len(found) - limit} more finding(s); raise limit or min_severity.")
    drifted = [d for d in plan.drift if d.kind in ("delete",)]
    if drifted:
        out.append(f"Note: {len(drifted)} resource(s) were deleted outside Terraform (see outputs_and_drift).")
    return clip("\n".join(out))


# ------------------------------------------------------------------ diff_resource

def _find(plan: Plan, address: str) -> list[Change]:
    if not address or len(address) > 5000:
        raise PlanError("address is empty or too long")
    hits = plan.find(address)
    if hits:
        return hits
    names = [c.address for c in plan.changes]
    close = difflib.get_close_matches(address, names, n=5, cutoff=0.5) if len(names) < 20000 else []
    sub = [n for n in names if address in n][:5]
    sugg = list(dict.fromkeys(sub + close))[:5]
    hint = ("; did you mean: " + ", ".join(addr(s) for s in sugg)) if sugg else ""
    raise PlanError(f"no resource change with address {addr(address)!r} in this plan{hint}. "
                    "Use list_changes to see addresses (keys in addresses are quoted, e.g. aws_x.y[\"key\"]).")


def describe(c: Change) -> list[str]:
    ln = [f"{addr(c.key)}  [{c.label}]  type={safe_text(c.type, 100)}"]
    if c.order:
        ln.append(f"  order: {c.order.replace('_', ' ')}")
    if c.reason:
        ln.append(f"  action_reason: {safe_text(c.reason, 100)}")
    if c.moved_from:
        ln.append(f"  moved from: {addr(c.moved_from)}")
    if c.importing:
        imp = c.change.get("importing")
        iid = imp.get("id") if isinstance(imp, dict) else None
        ln.append("  importing existing object" + (f" (id {safe_text(str(redact(str(iid))), 120)})" if iid else ""))
    rp = c.change.get("replace_paths")
    if isinstance(rp, list) and rp:
        ln.append("  replace_paths: " + ", ".join(fmt_replace_path(p) for p in rp[:10]))
    return ln


def diff_resource(plan: Plan, address: str, max_attributes: int = 200) -> str:
    max_attributes = max(1, min(max_attributes, 2000))
    out: list[str] = []
    for c in _find(plan, address):
        out += describe(c)
        ents, trunc = diff_change(c.change, limit=max_attributes)
        if not ents:
            out.append("  (no attribute-level differences)")
        for e in ents:
            out.append("  " + safe_text(render_entry(e), 700))
        if trunc:
            out.append(f"  ... truncated at {max_attributes} attributes; raise max_attributes")
        out.append("")
    out.append(f"Legend: {MASK} = Terraform marked it sensitive or its name looks like a credential; "
               f"{UNKNOWN} = decided at apply time.")
    return clip("\n".join(out))


# ------------------------------------------------------------------ list_changes

def list_changes(plan: Plan, action: str | None = None, type: str | None = None, module: str | None = None,
                 address: str | None = None, limit: int = 100, offset: int = 0) -> str:
    valid = set(KINDS) | {"import", "move"}
    if action is not None and action not in valid:
        raise PlanError(f"action must be one of {', '.join(sorted(valid))}")
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    trx = _glob(type) if type else None
    arx = _glob(address) if address else None
    sel: list[Change] = []
    for c in plan.changes:
        if action is None:
            if c.kind == "no-op" and not (c.importing or c.moved_from):
                continue
        elif action == "import":
            if not c.importing:
                continue
        elif action == "move":
            if not c.moved_from:
                continue
        elif c.kind != action:
            continue
        if trx and not trx.fullmatch(c.type):
            continue
        if arx and not arx.fullmatch(c.address):
            continue
        if module:
            if module == "root":
                if c.module != "root":
                    continue
            elif not (c.module == module or c.module.startswith(module + ".") or c.module.startswith(module + "[")):
                continue
        sel.append(c)
    page = sel[offset:offset + limit]
    out = [f"{len(sel)} matching change(s); showing {len(page)} from offset {offset}."
           + (" (pure no-ops are hidden unless action='no-op')" if action is None else "")]
    for c in page:
        extra = f"  <- {addr(c.moved_from)}" if c.moved_from else ""
        out.append(f"{c.label:<14} {addr(c.key)}{extra}")
    if offset + limit < len(sel):
        out.append(f"... use offset={offset + limit} for more")
    return clip("\n".join(out))


# ------------------------------------------------------------------ explain_replace

_REASONS = {
    "replace_because_cannot_update": "the provider cannot change the attribute(s) below in place (ForceNew), so the object must be rebuilt",
    "replace_because_tainted": "the object is marked tainted (a previous apply failed partway, or `terraform taint` was run)",
    "replace_by_request": "you asked for it with `-replace=ADDRESS`",
    "replace_by_triggers": "a lifecycle replace_triggered_by reference changed",
    "delete_because_no_resource_config": "the resource block was removed from the configuration",
    "delete_because_wrong_repetition": "count/for_each was added or removed on this resource",
    "delete_because_count_index": "its count index is now out of range",
    "delete_because_each_key": "its for_each key is no longer present",
    "delete_because_no_module": "the module call was removed from the configuration",
}


def split_address(a: str) -> list[str]:
    """Split an address on dots that are outside [...] and quotes."""
    parts, cur, depth, inq, esc = [], [], 0, False, False
    for ch in a:
        if inq:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                inq = False
            continue
        if ch == '"':
            inq = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == "." and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return parts


def _strip_index(t: str) -> str:
    return t.split("[", 1)[0]


def _config_module(raw: dict[str, Any], module: str) -> dict[str, Any] | None:
    cfg = raw.get("configuration")
    node = cfg.get("root_module") if isinstance(cfg, dict) else None
    if not isinstance(node, dict):
        return None
    if module == "root":
        return node
    toks = split_address(module)
    for i in range(0, len(toks) - 1, 2):
        calls = node.get("module_calls")
        call = calls.get(_strip_index(toks[i + 1])) if isinstance(calls, dict) else None
        sub = call.get("module") if isinstance(call, dict) else None
        if not isinstance(sub, dict):
            return None
        node = sub
    return node


def _local_address(c: Change) -> str:
    if c.module != "root" and c.address.startswith(c.module + "."):
        return c.address[len(c.module) + 1:]
    return c.address


def _refs(node: Any, depth: int = 0) -> list[str]:
    out: list[str] = []
    if depth > 12:
        return out
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "references" and isinstance(v, list):
                out += [x for x in v if isinstance(x, str)]
            else:
                out += _refs(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            out += _refs(v, depth + 1)
    return out


def _refers(refs: list[str], target: str) -> bool:
    return any(r == target or r.startswith(target + ".") or r.startswith(target + "[") for r in refs)


def explain_replace(plan: Plan, address: str) -> str:
    out: list[str] = []
    for c in _find(plan, address):
        if c.kind != "replace":
            out += describe(c)
            out.append(f"  This is not a replacement (action {'+'.join(c.actions)}); nothing to explain."
                       + (" Use diff_resource for the attribute changes." if c.kind == "update" else ""))
            out.append("")
            continue
        out += describe(c)
        ents, _ = diff_change(c.change, limit=1000)
        why = _REASONS.get(c.reason, safe_text(c.reason, 100) if c.reason else "")
        out.append(f"WHY: {why or 'no action_reason recorded (older Terraform); see replace_paths'}")
        rps = [tuple(p) for p in as_list(c.change.get("replace_paths")) if isinstance(p, list)]
        for rp in rps[:10]:
            hits = [e for e in ents if e.path[: len(rp)] == rp]
            label = fmt_path(rp)
            if hits:
                for e in hits[:3]:
                    out.append("  forcing change: " + safe_text(render_entry(e), 500))
            else:
                out.append(f"  forcing attribute: {label}")
        if not rps:
            out.append("  (no replace_paths: the trigger is not an attribute change)")
        if c.order == "delete_then_create":
            out.append("ORDER: destroy first, then create. There is a gap where the old object is gone and the new one does "
                       "not exist yet; destroy-time protections (deletion_protection, prevent_destroy) will stop the apply.")
        else:
            out.append("ORDER: create first, then destroy the old object (create_before_destroy). Both exist briefly, so "
                       "unique names / ports / CIDRs must not collide between old and new.")
        cfg = _config_module(plan.raw, c.module)
        local = _local_address(c)
        toks = split_address(local)
        key = ".".join(_strip_index(t) for t in toks)
        res = None
        if cfg:
            for r in as_list(cfg.get("resources")):
                if isinstance(r, dict) and r.get("address") == key:
                    res = r
        if res is None:
            out.append("CONFIG: configuration section does not contain this resource (or the plan has no configuration).")
        else:
            lc_raw = res.get("lifecycle")
            lc: dict[str, Any] = lc_raw if isinstance(lc_raw, dict) else {}
            cbd = lc.get("create_before_destroy", res.get("create_before_destroy"))
            if cbd is True:
                out.append("CONFIG: lifecycle create_before_destroy = true.")
            elif cbd is False:
                out.append("CONFIG: lifecycle create_before_destroy = false.")
            elif c.order == "delete_then_create":
                out.append("HINT: add `lifecycle { create_before_destroy = true }` if you need no gap (the JSON plan does not "
                           "record lifecycle settings, so this is inferred from the action order).")
            deps: list[str] = []
            if cfg:
                tgt = key
                for r in as_list(cfg.get("resources")):
                    if isinstance(r, dict) and r.get("address") != key and _refers(_refs(r), tgt):
                        deps.append(str(r.get("address")))
                calls = cfg.get("module_calls")
                if isinstance(calls, dict):
                    for n, call in calls.items():
                        if isinstance(call, dict) and _refers(_refs(call.get("expressions")), tgt):
                            deps.append(f"module.{n} (receives it as an input)")
                outs = cfg.get("outputs")
                if isinstance(outs, dict):
                    for n, o in outs.items():
                        if isinstance(o, dict) and _refers(_refs(o), tgt):
                            deps.append(f"output {n}")
            if deps:
                out.append(f"DEPENDENTS ({len(deps)}; same module, from configuration references):")
                prefix = "" if c.module == "root" else c.module + "."
                for d in deps[:25]:
                    if d.startswith("output ") or d.startswith("module."):
                        out.append(f"  - {addr(d)}")
                        continue
                    acts = [x for x in plan.changes if x.address.startswith(prefix + d + "[") or x.address == prefix + d]
                    status = ", ".join(sorted({x.label for x in acts})) if acts else "not in plan changes"
                    out.append(f"  - {addr(d)}  [{status}]")
                out.append("  A replacement gives the new object new computed values (ids, ARNs, addresses); dependents "
                           "that use them will show '(known after apply)' and are usually updated or replaced too.")
            else:
                out.append("DEPENDENTS: none found in the same module's configuration references.")
        out.append("")
    return clip("\n".join(out))


# ------------------------------------------------------------------ compare_plans

def _fingerprint(c: Change) -> str:
    ch = c.change
    return json.dumps([ch.get("actions"), ch.get("after"), ch.get("after_unknown"), ch.get("replace_paths")],
                      sort_keys=True, default=str)


def compare_plans(a: Plan, b: Plan, limit: int = 50) -> str:
    limit = max(1, min(limit, 500))
    ia = {c.key: c for c in a.changes if c.kind != "no-op"}
    ib = {c.key: c for c in b.changes if c.kind != "no-op"}
    added = sorted(set(ib) - set(ia))
    removed = sorted(set(ia) - set(ib))
    both = sorted(set(ia) & set(ib))
    action_changed = [k for k in both if ia[k].actions != ib[k].actions]
    value_changed = [k for k in both if ia[k].actions == ib[k].actions and _fingerprint(ia[k]) != _fingerprint(ib[k])]
    out = [f"Compare: A has {len(ia)} real change(s), B has {len(ib)}. "
           f"New in B: {len(added)}; gone in B: {len(removed)}; different action: {len(action_changed)}; "
           f"same action but different planned values: {len(value_changed)}; identical: "
           f"{len(both) - len(action_changed) - len(value_changed)}."]
    ta, tb = a.raw.get("terraform_version"), b.raw.get("terraform_version")
    if ta != tb:
        out.append(f"Note: terraform_version differs (A {ta}, B {tb}); some differences may be version noise.")
    if _cfg_fp(a) != _cfg_fp(b):
        out.append("Note: the embedded configuration differs, so these plans are of different code, not just different state.")

    def section(title: str, keys: list[str], fmt: Any) -> None:
        if not keys:
            return
        out.append(f"{title} ({len(keys)}):")
        for k in keys[:limit]:
            out.append("  " + safe_text(fmt(k), 600))
        if len(keys) > limit:
            out.append(f"  ... {len(keys) - limit} more")

    section("New in B (not in A)", added, lambda k: f"{k}  [{ib[k].label}]")
    section("Gone in B (was in A)", removed, lambda k: f"{k}  [{ia[k].label}]")
    section("Action changed", action_changed, lambda k: f"{k}  A={ia[k].label} -> B={ib[k].label}")
    if value_changed:
        out.append(f"Same action, different planned values ({len(value_changed)}):")
        for k in value_changed[:limit]:
            out.append(f"  {addr(k)}  [{ib[k].label}]")
            ua = ia[k].change.get("after_unknown", {})
            ub = ib[k].change.get("after_unknown", {})
            syn = {
                "actions": ["update"],
                "before": ia[k].change.get("after"),
                "after": ib[k].change.get("after"),
                "after_unknown": {} if ua == ub else ub,
                "before_sensitive": ia[k].change.get("after_sensitive", {}),
                "after_sensitive": ib[k].change.get("after_sensitive", {}),
            }
            ents, trunc = diff_change(syn, limit=8)
            for e in ents:
                out.append("      A->B " + safe_text(render_entry(e), 500))
            if trunc:
                out.append("      ...")
        if len(value_changed) > limit:
            out.append(f"  ... {len(value_changed) - limit} more")
    oa, ob = a.raw.get("output_changes"), b.raw.get("output_changes")
    oa = oa if isinstance(oa, dict) else {}
    ob = ob if isinstance(ob, dict) else {}
    odiff = sorted(set(oa) ^ set(ob))
    if odiff:
        out.append("Output changes present in only one plan: " + ", ".join(addr(x) for x in odiff[:30]))
    return clip("\n".join(out))


def _cfg_fp(p: Plan) -> str:
    return json.dumps(p.raw.get("configuration"), sort_keys=True, default=str)


# ------------------------------------------------------------------ outputs_and_drift

def outputs_and_drift(plan: Plan, limit: int = 50) -> str:
    limit = max(1, min(limit, 500))
    out: list[str] = []
    oc = plan.raw.get("output_changes")
    if isinstance(oc, dict) and oc:
        out.append(f"OUTPUT CHANGES ({len(oc)}):")
        for i, (name, ch) in enumerate(sorted(oc.items())):
            if i >= limit:
                out.append(f"  ... {len(oc) - limit} more")
                break
            if not isinstance(ch, dict):
                out.append(f"  {addr(str(name))}: (malformed)")
                continue
            ents, _ = diff_change(ch, limit=10, secret_name=name_is_secret(name))
            acts = "+".join(a for a in ch.get("actions", []) if isinstance(a, str))
            out.append(f"  output {safe_text(str(name), 120)}  [{acts}]")
            for e in ents:
                out.append("      " + safe_text(render_entry(e), 500))
    else:
        out.append("OUTPUT CHANGES: none.")
    out.append("")
    if plan.drift:
        out.append(f"DRIFT: {len(plan.drift)} resource(s) changed outside Terraform since the last apply/refresh.")
        planned = {c.address for c in plan.changes if c.kind != "no-op"}
        for c in plan.drift[:limit]:
            out += ["  " + ln for ln in describe(c)]
            ents, trunc = diff_change(c.change, limit=15)
            for e in ents:
                out.append("      " + safe_text(render_entry(e), 500))
            if trunc:
                out.append("      ...")
            if c.address in planned:
                out.append("      (this resource also has a planned change in this run)")
        if len(plan.drift) > limit:
            out.append(f"  ... {len(plan.drift) - limit} more")
    else:
        out.append("DRIFT: none. (Plans created with -refresh=false never report drift.)")
    return clip("\n".join(out))

