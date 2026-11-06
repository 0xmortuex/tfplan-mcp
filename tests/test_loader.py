import json
import os
import sys
import zipfile

import pytest
from conftest import FIXDIR, fx

from tfplan_mcp import analysis, loader
from tfplan_mcp.loader import PlanError


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    loader.settings.root = loader.real(str(tmp_path))
    return str(p)


def test_all_fixtures_load_and_summarize():
    names = [f for f in os.listdir(FIXDIR) if f.endswith(".json")]
    assert len(names) >= 14
    for n in names:
        text = analysis.plan_summary(loader.load(fx(n[:-5])))
        assert "format_version" in text


def test_state_file_is_detected(tmp_path):
    state = {"format_version": "1.0", "terraform_version": "1.9.0",
             "values": {"root_module": {"resources": []}}}
    p = write(tmp_path, "state.json", json.dumps(state))
    with pytest.raises(PlanError, match="STATE"):
        loader.load(p)


def test_raw_tfstate_detected(tmp_path):
    p = write(tmp_path, "s.tfstate", json.dumps({"version": 4, "resources": [], "serial": 1}))
    with pytest.raises(PlanError, match="raw terraform.tfstate"):
        loader.load(p)


def test_ui_log_detected(tmp_path):
    line1 = '{"@level":"info","@message":"Terraform 1.9.0","type":"version"}\n'
    p = write(tmp_path, "log.json", line1 + line1)
    with pytest.raises(PlanError, match="plan -json"):
        loader.load(p)


def test_binary_plan_detected(tmp_path):
    zp = tmp_path / "tfplan"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("tfplan", "x")
    loader.settings.root = loader.real(str(tmp_path))
    with pytest.raises(PlanError, match="binary plan"):
        loader.load(str(zp))


def test_random_json_and_garbage(tmp_path):
    with pytest.raises(PlanError, match="not a Terraform plan"):
        loader.load(write(tmp_path, "a.json", '{"hello": 1}'))
    with pytest.raises(PlanError, match="not a Terraform plan"):
        loader.load(write(tmp_path, "b.json", '{"format_version": "1.2"}'))
    with pytest.raises(PlanError, match="top level"):
        loader.load(write(tmp_path, "c.json", "[1,2]"))
    with pytest.raises(PlanError, match="not valid JSON"):
        loader.load(write(tmp_path, "d.json", "{oops"))
    with pytest.raises(PlanError, match="not valid JSON"):
        loader.load(write(tmp_path, "e.json", ""))
    with pytest.raises(PlanError, match="UTF-8"):
        loader.load(write(tmp_path, "f.json", b"\xff\xfe\x00\x80\x81"))
    with pytest.raises(PlanError, match="unsupported plan format_version"):
        loader.load(write(tmp_path, "g.json", '{"format_version": "2.0", "resource_changes": []}'))


def test_nan_infinity_rejected(tmp_path):
    body = ('{"format_version":"1.2","resource_changes":[{"address":"a.b",'
            '"change":{"actions":["create"],"after":{"x":NaN}}}]}')
    with pytest.raises(PlanError, match="NaN"):
        loader.load(write(tmp_path, "nan.json", body))


def test_huge_numbers_do_not_crash(tmp_path):
    big = "9" * 6000
    body = ('{"format_version":"1.2","resource_changes":[{"address":"a.b","type":"a","change":{"actions":["create"],'
            '"before":null,"after":{"n":' + big + ',"f":1e999,"ok":12345678901234567890}}}]}')
    plan = loader.load(write(tmp_path, "big.json", body))
    out = analysis.diff_resource(plan, "a.b")
    assert "huge integer, 6000 digits" in out and "12345678901234567890" in out
    assert "Infinity" in out


def test_deeply_nested_json_is_a_clean_error(tmp_path):
    body = '{"format_version":"1.2","x":' + "[" * 200000 + "]" * 200000 + "}"
    with pytest.raises(PlanError, match="nested too deeply"):
        loader.load(write(tmp_path, "deep.json", body))


def test_moderately_deep_values_do_not_crash_the_diff(tmp_path):
    nested = "leaf"
    for _ in range(300):
        nested = {"k": nested}
    body = {"format_version": "1.2", "resource_changes": [
        {"address": "a.b", "type": "a",
         "change": {"actions": ["create"], "before": None, "after": {"v": nested}}}]}
    plan = loader.load(write(tmp_path, "nest.json", json.dumps(body)))
    assert "nested too deep" in analysis.diff_resource(plan, "a.b")


def test_size_limit_message(tmp_path):
    p = write(tmp_path, "p.json",
              json.dumps({"format_version": "1.2", "resource_changes": [], "pad": "x" * 200000}))
    loader.settings.max_bytes = 100_000
    with pytest.raises(PlanError, match="--max-mb"):
        loader.load(p)


def test_utf8_bom_is_accepted(tmp_path):
    body = b"\xef\xbb\xbf" + json.dumps({"format_version": "1.2", "resource_changes": []}).encode()
    assert "EMPTY plan" in analysis.plan_summary(loader.load(write(tmp_path, "bom.json", body)))


def test_malformed_entries_are_counted_not_hidden(tmp_path):
    body = {"format_version": "1.2", "resource_changes": [
        {"address": "ok.a", "type": "ok", "change": {"actions": ["create"]}}, 5, {"address": 3}]}
    out = analysis.plan_summary(loader.load(write(tmp_path, "m.json", json.dumps(body))))
    assert "2 resource_changes/resource_drift entries were malformed" in out


def test_sandbox_blocks_escape(tmp_path):
    sub = tmp_path / "inside"
    sub.mkdir()
    (tmp_path / "outside.json").write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))
    (sub / "ok.json").write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))
    loader.settings.root = loader.real(str(sub))
    loader.load("ok.json")
    for bad in ("../outside.json", str(tmp_path / "outside.json"), "..\\outside.json", "inside/../../outside.json"):
        with pytest.raises(PlanError, match="outside the allowed directory|not found"):
            loader.load(bad)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_sandbox_blocks_symlink_escape(tmp_path):
    sub = tmp_path / "inside"
    sub.mkdir()
    (tmp_path / "outside.json").write_text("{}")
    os.symlink(tmp_path / "outside.json", sub / "link.json")
    loader.settings.root = loader.real(str(sub))
    with pytest.raises(PlanError, match="outside the allowed directory"):
        loader.load("link.json")


def test_huge_path_is_a_clean_error():
    for p in ("a" * 100_000, ("sub/" * 25_000) + "x.json", "x\x00y"):
        with pytest.raises(PlanError):
            loader.load(p)


def test_missing_and_directory_and_empty():
    with pytest.raises(PlanError, match="not found"):
        loader.load("nope.json")
    with pytest.raises(PlanError, match="empty"):
        loader.load("  ")
    with pytest.raises(PlanError, match="not a file"):
        loader.load(".")


def test_cache_invalidates_on_change(tmp_path):
    p = write(tmp_path, "c.json", json.dumps({"format_version": "1.2", "resource_changes": []}))
    assert "EMPTY" in analysis.plan_summary(loader.load(p))
    body = {"format_version": "1.2", "resource_changes": [
        {"address": "a.b", "type": "a", "change": {"actions": ["create"], "before": None, "after": {}}}]}
    with open(p, "w", encoding="utf-8") as f:
        json.dump(body, f)
        f.write("  ")
    assert "create 1" in analysis.plan_summary(loader.load(p))


def test_large_plan_parses_and_summarizes(tmp_path):
    changes = [{"address": f"aws_instance.n[{i}]", "type": "aws_instance", "name": "n", "index": i,
                "change": {"actions": ["create"], "before": None,
                           "after": {"ami": f"ami-{i}", "tags": {f"k{j}": "v" * 20 for j in range(10)}},
                           "after_unknown": {"id": True}, "before_sensitive": False, "after_sensitive": {}}}
               for i in range(40000)]
    p = write(tmp_path, "large.json", json.dumps({"format_version": "1.2", "resource_changes": changes}))
    assert os.path.getsize(p) > 15_000_000
    plan = loader.load(p)
    assert "create 40000" in analysis.plan_summary(plan)
    assert "showing 100" in analysis.list_changes(plan)
