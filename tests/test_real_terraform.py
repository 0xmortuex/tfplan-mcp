"""OPTIONAL: generate a real plan with a local terraform/tofu binary.

Skipped unless TFPLAN_REAL_TERRAFORM=1 and a binary is on PATH. Uses only the built-in
terraform_data resource (no providers are downloaded). Not run in CI.
"""

import os
import shutil
import subprocess

import pytest

from tfplan_mcp import analysis, loader

BIN = shutil.which("terraform") or shutil.which("tofu")

pytestmark = [
    pytest.mark.real_terraform,
    pytest.mark.skipif(os.environ.get("TFPLAN_REAL_TERRAFORM") != "1" or not BIN,
                       reason="set TFPLAN_REAL_TERRAFORM=1 and install terraform/tofu to run"),
]


def test_real_plan_round_trip(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "terraform_data" "a" {\n  input = "hello"\n}\n'
        'resource "terraform_data" "b" {\n  count = 2\n  input = terraform_data.a.id\n}\n'
        'output "o" {\n  value = terraform_data.a.input\n}\n',
        encoding="utf-8",
    )
    run = lambda *a: subprocess.run([BIN, *a], cwd=tmp_path, capture_output=True, text=True, check=True)  # noqa: E731
    run("init", "-input=false")
    run("plan", "-input=false", "-out=tfplan")
    shown = run("show", "-json", "tfplan").stdout
    (tmp_path / "plan.json").write_text(shown, encoding="utf-8")
    loader.settings.root = loader.real(str(tmp_path))
    plan = loader.load("plan.json")
    out = analysis.plan_summary(plan)
    assert "create 3" in out
    assert "(known after apply)" in analysis.diff_resource(plan, "terraform_data.b[0]")
    assert "output o" in analysis.outputs_and_drift(plan)
