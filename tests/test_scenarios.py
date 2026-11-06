import json
import os

import pytest
from conftest import FIXDIR, SECRET, fx

from tfplan_mcp import analysis, loader
from tfplan_mcp.loader import PlanError
from tfplan_mcp.mask import name_is_secret


def P(name):
    return loader.load(fx(name))


def test_empty_plan():
    out = analysis.plan_summary(P("empty"))
    assert "EMPTY plan" in out and "terraform_version 1.5.7" in out
    assert "no findings" in analysis.risky_changes(P("empty"))
    assert "0 matching" in analysis.list_changes(P("empty"))


def test_create_only_summary():
    out = analysis.plan_summary(P("create_only"))
    assert "2 real change(s) [create 2]" in out
    assert "aws_vpc: create 1" in out and "DESTROY" not in out
    assert "no findings" in analysis.risky_changes(P("create_only"))


def test_in_place_update_and_tags_only_demoted():
    out = analysis.diff_resource(P("in_place_update"), "aws_instance.web")
    assert '~ instance_type: "t3.micro" -> "t3.small"' in out
    risk = analysis.risky_changes(P("in_place_update"))
    assert "[LOW] aws_s3_bucket.logs" in risk and "tags/labels-only" in risk
    assert "aws_instance.web" not in risk


def test_forced_replacement_attribute_and_reason():
    risk = analysis.risky_changes(P("forced_replace"))
    assert "[CRITICAL] aws_db_instance.main" in risk
    assert "forced by change to: engine" in risk and "replace_because_cannot_update" in risk
    ex = analysis.explain_replace(P("forced_replace"), "aws_db_instance.main")
    assert 'engine: "postgres" -> "mysql"' in ex
    assert "destroy first, then create" in ex
    assert "aws_route53_record.db  [update]" in ex and "output db_host" in ex
    assert "create_before_destroy" in ex
    cbd = analysis.explain_replace(P("forced_replace"), "aws_instance.app")
    assert "create first, then destroy" in cbd
    assert "not a replacement" in analysis.explain_replace(P("forced_replace"), "aws_route53_record.db")


def test_destroy_database_ranked_first():
    plan = P("destroy_database")
    assert "DESTROY PLAN" in analysis.plan_summary(plan)
    risk = analysis.risky_changes(plan)
    lines = [ln for ln in risk.splitlines() if ln[:2] in ("1.", "2.", "3.", "4.")]
    assert "aws_db_instance.prod" in lines[0] or "aws_kms_key" in lines[0] or "aws_s3_bucket" in lines[0]
    assert "[CRITICAL]" in lines[0] and "[MEDIUM] aws_security_group.old" in lines[-1]
    assert "data held by it is lost" in risk
    assert "delete_because_no_resource_config" in risk


def test_iam_broadening():
    risk = analysis.risky_changes(P("iam_broadening"))
    assert "Action '*' on Resource '*'" in risk
    assert "AdministratorAccess" in risk
    assert "Principal '*'" in risk
    assert "allUsers" in risk


def test_iam_narrowing_not_flagged(tmp_path):
    broad = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    narrow = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:x"}]})
    body = {"format_version": "1.2", "resource_changes": [{
        "address": "aws_iam_policy.p", "type": "aws_iam_policy", "name": "p",
        "change": {"actions": ["update"], "before": {"policy": broad}, "after": {"policy": narrow}}}]}
    p = tmp_path / "n.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    loader.settings.root = loader.real(str(tmp_path))
    assert "no findings" in analysis.risky_changes(loader.load(str(p)))


def test_security_groups_open_to_world():
    risk = analysis.risky_changes(P("sg_open"))
    assert "admin port(s) 22/SSH" in risk
    assert "data-service port(s) 5432/PostgreSQL" in risk
    assert "opens ALL ports" in risk
    assert "3389/RDP" in risk
    assert "aws_security_group_rule.out" not in risk, "egress must not be flagged"
    # 443 already open before and after: not a new finding
    assert "port 443" not in risk


def test_exposure_encryption_retention_deletion_protection():
    risk = analysis.risky_changes(P("exposure_misc"))
    for needle in ("public access enabled (publicly_accessible", "encryption/secure transport disabled (storage_encrypted",
                   "deletion protection turned off", "retention reduced (backup_retention_period: 14 -> 1)",
                   "encryption key changed (kms_key_id)", "public access block weakened (block_public_acls"):
        assert needle in risk, needle


def test_unknown_values_shown():
    out = analysis.diff_resource(P("unknown_values"), "aws_instance.web")
    assert "+ id: (known after apply)" in out
    assert "root_block_device[0].volume_id: (known after apply)" in out
    assert "tags_all.Name: (known after apply)" in out
    eip = analysis.diff_resource(P("unknown_values"), "aws_eip.web")
    assert '~ instance: "i-old" -> (known after apply)' in eip


def test_module_nesting_and_filters():
    plan = P("modules")
    out = analysis.plan_summary(plan)
    assert "module.network: create 1" in out and "root: update 1" in out
    assert "module.network.module.subnets[\"a\"]: create 1" in out
    nested = analysis.list_changes(plan, module="module.network")
    assert "2 matching" in nested
    assert "1 matching" in analysis.list_changes(plan, module="root")
    assert "1 matching" in analysis.list_changes(plan, module='module.network.module.subnets["a"]')
    assert "1 matching" in analysis.list_changes(plan, type="aws_su*")
    assert "1 matching" in analysis.list_changes(plan, action="update")


def test_count_foreach_quotes_unicode_brackets():
    plan = P("count_foreach")
    assert "5 matching" in analysis.list_changes(plan)
    assert "2 matching" in analysis.list_changes(plan, address="aws_instance.n[*")
    assert "1 matching" in analysis.list_changes(plan, address='aws_s3_bucket.b["a.b[c]"]')
    out = analysis.diff_resource(plan, 'aws_s3_bucket.b["café-日本"]')
    assert '- bucket: "u"' in out
    out = analysis.diff_resource(plan, 'aws_s3_bucket.b["a.b[c]"]')
    assert "~ force_destroy: false -> true" in out
    assert "force_destroy enabled" in analysis.risky_changes(plan)
    with pytest.raises(PlanError, match="did you mean"):
        analysis.diff_resource(plan, 'aws_s3_bucket.b["cafe"]')


def test_drift_and_outputs():
    out = analysis.outputs_and_drift(P("drift"))
    assert "DRIFT: 2 resource(s)" in out and '~ instance_type: "t3.micro" -> "t3.small"' in out
    assert "also has a planned change" in out
    assert '~ (value): "1.1.1.1" -> (known after apply)' in out
    assert "Drift: 2 resource" in analysis.plan_summary(P("drift"))
    assert "Note: 1 resource(s) were deleted outside Terraform" in analysis.risky_changes(P("drift"))


def test_noop_moved_import_forget():
    plan = P("noop_moved_import")
    out = analysis.plan_summary(plan)
    assert "moved 1, imported 1" in out and "forgotten" in out
    assert "DESTROY PLAN" not in out
    lst = analysis.list_changes(plan)
    assert "aws_instance.new_name  <- aws_instance.old_name" in lst
    assert "aws_instance.same" not in lst
    assert "1 matching" in analysis.list_changes(plan, action="import")
    assert "1 matching" in analysis.list_changes(plan, action="move")
    assert "4 matching" not in analysis.list_changes(plan, action="no-op")
    assert "removed from state" in analysis.risky_changes(plan)
    d = analysis.diff_resource(plan, "aws_s3_bucket.adopted")
    assert "importing existing object" in d and "no attribute-level differences" in d


def test_errored_and_deferred_warnings():
    out = analysis.plan_summary(P("errored_deferred"))
    for needle in ("ERRORED", "applyable=false", "complete=false", "DEFERRED", "check block(s) are failing"):
        assert needle in out


def test_compare_plans():
    a, b = P("in_place_update"), P("in_place_update")
    assert "New in B: 0; gone in B: 0; different action: 0" in analysis.compare_plans(a, b)
    out = analysis.compare_plans(P("create_only"), P("in_place_update"))
    assert "aws_vpc.main" in out and "Gone in B" in out and "New in B" in out


def test_compare_plans_detects_value_and_action_change(tmp_path):
    def mk(actions, it, pw):
        return {"format_version": "1.2", "resource_changes": [{
            "address": "aws_instance.w", "type": "aws_instance", "name": "w",
            "change": {"actions": actions, "before": {"t": "a"}, "after": {"t": it, "password": pw},
                       "after_unknown": {}, "before_sensitive": {}, "after_sensitive": {"password": True}}}]}
    paths = []
    for i, body in enumerate([mk(["update"], "x", SECRET + "1"), mk(["update"], "y", SECRET + "2"),
                              mk(["delete", "create"], "y", SECRET + "3")]):
        p = tmp_path / f"p{i}.json"
        p.write_text(json.dumps(body), encoding="utf-8")
        paths.append(str(p))
    loader.settings.root = loader.real(str(tmp_path))
    out = analysis.compare_plans(loader.load(paths[0]), loader.load(paths[1]))
    assert "same action but different planned values: 1" in out and '~ t: "x" -> "y"' in out
    assert "(sensitive) -> (sensitive)" in out and SECRET not in out
    out = analysis.compare_plans(loader.load(paths[1]), loader.load(paths[2]))
    assert "A=update -> B=replace" in out


def test_list_changes_validation_and_paging():
    with pytest.raises(PlanError, match="action must be one of"):
        analysis.list_changes(P("modules"), action="explode")
    out = analysis.list_changes(P("count_foreach"), limit=2, offset=1)
    assert "showing 2 from offset 1" in out and "offset=3" in out
    with pytest.raises(PlanError, match="min_severity"):
        analysis.risky_changes(P("modules"), "bogus")


def test_name_heuristic():
    for n in ("password", "db_password", "master_token", "api_key", "secret_string", "private_key", "client_secret",
              "key", "access_key_id", "Authorization", "connection_string"):
        assert name_is_secret(n), n
    for n in ("name", "instance_type", "monkeys", "keeper", "ami", "tags", "bucket", "enable_key_rotation_x_ok"[:6]):
        assert not name_is_secret(n), n


def test_fixture_files_are_utf8_lf():
    for f in os.listdir(FIXDIR):
        raw = open(os.path.join(FIXDIR, f), "rb").read()
        raw.decode("utf-8")
        assert b"\r\n" not in raw
