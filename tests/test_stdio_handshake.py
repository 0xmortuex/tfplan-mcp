"""Launches the real server over stdio, lists tools, calls them, and checks that
errors reach the agent and that planted secrets never do."""

import json
import subprocess
import sys

import pytest
from conftest import FIXDIR, SECRET

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "plan_summary", "risky_changes", "diff_resource", "list_changes",
    "explain_replace", "compare_plans", "outputs_and_drift",
}


def params(*extra):
    return StdioServerParameters(command=sys.executable, args=["-m", "tfplan_mcp", "--dir", FIXDIR, *extra])


def text(res):
    return "\n".join(getattr(c, "text", "") for c in res.content)


@pytest.mark.anyio
async def test_tools_and_calls_over_stdio():
    async with stdio_client(params()) as (r, w), ClientSession(r, w) as s:
        init = await s.initialize()
        assert init.server_info.name == "tfplan"
        tools = (await s.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(t.description and len(t.description) > 80 for t in tools)

        res = await s.call_tool("plan_summary", {"path": "destroy_database.json"})
        assert not res.is_error and "DESTROY PLAN" in text(res)
        res = await s.call_tool("risky_changes", {"path": "sg_open.json"})
        assert "22/SSH" in text(res)
        res = await s.call_tool("list_changes", {"path": "count_foreach.json", "action": "delete"})
        assert "caf\u00e9-\u65e5\u672c" in text(res)
        res = await s.call_tool("explain_replace", {"path": "forced_replace.json", "address": "aws_db_instance.main"})
        assert "ForceNew" in text(res)
        res = await s.call_tool("compare_plans", {"path_a": "create_only.json", "path_b": "modules.json"})
        assert "New in B" in text(res)
        res = await s.call_tool("outputs_and_drift", {"path": "drift.json"})
        assert "DRIFT: 2" in text(res)


@pytest.mark.anyio
async def test_planted_secrets_never_cross_the_wire():
    async with stdio_client(params()) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        blobs = []
        for tool, args in [
            ("plan_summary", {"path": "sensitive.json"}),
            ("risky_changes", {"path": "sensitive.json", "min_severity": "info"}),
            ("list_changes", {"path": "sensitive.json"}),
            ("diff_resource", {"path": "sensitive.json", "address": "aws_db_instance.main"}),
            ("diff_resource", {"path": "sensitive.json", "address": "aws_secretsmanager_secret_version.s"}),
            ("diff_resource", {"path": "destroy_database.json", "address": "aws_db_instance.prod"}),
            ("explain_replace", {"path": "sensitive.json", "address": "aws_db_instance.main"}),
            ("compare_plans", {"path_a": "sensitive.json", "path_b": "destroy_database.json"}),
            ("outputs_and_drift", {"path": "sensitive.json"}),
        ]:
            res = await s.call_tool(tool, args)
            assert not res.is_error, (tool, text(res))
            blobs.append(res.model_dump_json())
            blobs.append(text(res))
        joined = "\n".join(blobs)
        assert SECRET not in joined and "hunter2" not in joined
        assert "(sensitive)" in joined


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"format_version": "1.0", "values": {"root_module": {}}}), encoding="utf-8")
    async with stdio_client(params()) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        res = await s.call_tool("plan_summary", {"path": str(state)})
        assert res.is_error and "outside the allowed directory" in text(res)
        res = await s.call_tool("plan_summary", {"path": "../../etc/passwd"})
        assert res.is_error and "outside the allowed directory" in text(res)
        res = await s.call_tool("plan_summary", {"path": "missing.json"})
        assert res.is_error and "file not found" in text(res)
        res = await s.call_tool("diff_resource", {"path": "modules.json", "address": "aws_vpc.nope"})
        assert res.is_error and "no resource change with address" in text(res)
        res = await s.call_tool("risky_changes", {"path": "modules.json", "min_severity": "x"})
        assert res.is_error and "min_severity must be one of" in text(res)


@pytest.mark.anyio
async def test_state_file_error_over_stdio(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"format_version": "1.0", "values": {"root_module": {}}}), encoding="utf-8")
    p = StdioServerParameters(command=sys.executable, args=["-m", "tfplan_mcp", "--dir", str(tmp_path)])
    async with stdio_client(p) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        res = await s.call_tool("plan_summary", {"path": "state.json"})
        assert res.is_error and "is a STATE" in text(res) and "not a plan" in text(res)


@pytest.mark.anyio
async def test_max_mb_flag_over_stdio(tmp_path):
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"format_version": "1.2", "resource_changes": [], "pad": "x" * 50000}), encoding="utf-8")
    p = StdioServerParameters(command=sys.executable,
                              args=["-m", "tfplan_mcp", "--dir", str(tmp_path), "--max-mb", "0.01"])
    async with stdio_client(p) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        res = await s.call_tool("plan_summary", {"path": "big.json"})
        assert res.is_error and "limit" in text(res) and "--max-mb" in text(res)


def test_bad_dir_flag_exits_cleanly():
    out = subprocess.run([sys.executable, "-m", "tfplan_mcp", "--dir", "Z:/definitely/not/here"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 2 and "not a directory" in out.stderr


def test_help_and_version():
    out = subprocess.run([sys.executable, "-m", "tfplan_mcp", "--version"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "tfplan-mcp 0.1.0" in out.stdout
