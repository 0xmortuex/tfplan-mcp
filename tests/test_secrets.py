"""Planted fake secrets must never appear in any output, via any tool, on any fixture."""

import json
import os

from conftest import FIXDIR, SECRET, fx

from tfplan_mcp import analysis, loader
from tfplan_mcp.diff import diff_change
from tfplan_mcp.mask import MASK, redact, scrub_string


def all_outputs(name):
    plan = loader.load(fx(name))
    outs = [analysis.plan_summary(plan), analysis.risky_changes(plan, "info", 500),
            analysis.outputs_and_drift(plan), analysis.list_changes(plan, action=None),
            analysis.list_changes(plan, action="no-op")]
    for c in plan.changes:
        outs.append(analysis.diff_resource(plan, c.address))
        outs.append(analysis.explain_replace(plan, c.address))
    outs.append(analysis.compare_plans(plan, plan))
    return outs


def test_no_fixture_leaks_any_secret_through_any_tool():
    seen = 0
    for f in sorted(os.listdir(FIXDIR)):
        for out in all_outputs(f[:-5]):
            assert SECRET not in out, (f, out[:300])
            assert "hunter2" not in out
            seen += 1
    assert seen > 100


def test_sensitive_fixture_shows_masks_not_values():
    plan = loader.load(fx("sensitive"))
    out = analysis.diff_resource(plan, "aws_db_instance.main")
    assert "~ password: (sensitive) -> (sensitive)" in out
    assert "~ master_token: (sensitive) -> (sensitive)" in out, "name heuristic: not flagged by terraform"
    assert "~ settings.credentials: (sensitive) -> (sensitive)" in out
    assert "tags.secret_key: (sensitive)" in out, "map key with secret-looking name"
    assert "+ note: (sensitive)" in out, "flagged only by Terraform's mask"
    assert "postgres://admin:(sensitive)@db.internal/app" in out, "URL credentials scrubbed"
    assert "settings.size: 1 -> 2" in out
    sec = analysis.diff_resource(plan, "aws_secretsmanager_secret_version.s")
    assert "+ secret_string: (sensitive)" in sec and '+ secret_id: (sensitive)' in sec
    od = analysis.outputs_and_drift(plan)
    assert "(sensitive)" in od and SECRET not in od


def test_variables_section_is_never_printed():
    # the fixture plans carry the secret in top-level `variables`
    raw = json.load(open(fx("sensitive"), encoding="utf-8"))
    assert raw["variables"]["db_password"]["value"] == SECRET
    for out in all_outputs("sensitive"):
        assert "db_password" not in out.replace("output db_password", "")


def test_unflagged_value_with_secret_name_masked_at_depth():
    ch = {"actions": ["create"], "before": None,
          "after": {"cfg": [{"inner": {"my_api_key": "S3CR3T", "password_hash": ["a", "b"], "ok": "fine"}}]},
          "after_unknown": {}, "after_sensitive": {}}
    ents, _ = diff_change(ch)
    text = " ".join(e.after for e in ents)
    assert "S3CR3T" not in text and '"a"' not in text and "fine" in text


def test_sensitive_mask_shapes():
    # nested list/dict mask, whole-value mask, and mask over unknown
    v = {"a": [1, {"b": "x"}], "c": "y"}
    r = redact(v, {"a": [False, {"b": True}], "c": False})
    assert r == {"a": [1, {"b": MASK}], "c": "y"}
    assert redact(v, True) == MASK
    assert scrub_string("-----BEGIN RSA PRIVATE KEY-----\nabc") == MASK
    assert scrub_string("AKIAABCDEFGHIJKLMNOP") == MASK
    assert scrub_string("hello") == "hello"


def test_sensitive_before_plain_after_does_not_leak_before(tmp_path):
    body = {"format_version": "1.2", "resource_changes": [{
        "address": "x.y", "type": "x", "name": "y",
        "change": {"actions": ["update"], "before": {"v": "OLDSECRETVALUE"}, "after": {"v": "plain-new"},
                   "after_unknown": {}, "before_sensitive": {"v": True}, "after_sensitive": {}}}]}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    loader.settings.root = loader.real(str(tmp_path))
    out = analysis.diff_resource(loader.load(str(p)), "x.y")
    assert "OLDSECRETVALUE" not in out and "(sensitive) ->" in out


def test_risk_findings_never_copy_policy_text(tmp_path):
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                                     "Sid": "token-" + SECRET}]})
    body = {"format_version": "1.2", "resource_changes": [{
        "address": "aws_iam_policy.p", "type": "aws_iam_policy", "name": "p",
        "change": {"actions": ["create"], "before": None, "after": {"policy": pol, "name": "p"},
                   "after_unknown": {}, "after_sensitive": {}}}]}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    loader.settings.root = loader.real(str(tmp_path))
    plan = loader.load(str(p))
    assert SECRET not in analysis.risky_changes(plan)  # findings never copy policy text
    assert "full administrator" in analysis.risky_changes(plan)
