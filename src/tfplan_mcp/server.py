"""tfplan-mcp: read and risk-review a Terraform/OpenTofu plan. Read-only; never runs terraform."""

from __future__ import annotations

import argparse
import functools
import sys
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__, analysis, loader
from .loader import PlanError

mcp = MCPServer(
    "tfplan",
    instructions=(
        "Review a Terraform/OpenTofu plan without running terraform. The input is the JSON from "
        "`terraform show -json tfplan > plan.json` (pass its path as `path`). Start with plan_summary, "
        "then risky_changes for a ranked list of dangerous changes (destroyed databases/buckets/keys, "
        "forced replacements, IAM broadening, 0.0.0.0/0 on admin ports, public access, encryption or "
        "deletion-protection downgrades). Drill into one resource with diff_resource or explain_replace, "
        "browse with list_changes, compare two plans with compare_plans, and see output changes and "
        "drift with outputs_and_drift. Sensitive values are always shown as (sensitive). "
        "Everything is read-only; the server never contacts a cloud or provider."
    ),
)

F = TypeVar("F", bound=Callable[..., Any])


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except PlanError as e:
            raise ToolError(str(e)) from e
        except MemoryError as e:
            raise ToolError("ran out of memory loading the plan; raise RAM or trim the plan") from e

    mcp.tool()(wrapper)
    return fn


@tool
def plan_summary(path: str) -> str:
    """Overview of a plan: counts of create/update/delete/replace/read/forget/no-op by resource
    type and module, whether it is an empty or destroy plan, moved/imported resources, drift,
    output changes, failing checks, terraform version and warnings (errored, incomplete,
    deferred changes). Call this first.

    path: plan JSON from `terraform show -json tfplan` (relative to the server's --dir).
    Files over the size limit (256 MB default, --max-mb) are refused with a clear error.
    """
    return analysis.plan_summary(loader.load(path))


@tool
def risky_changes(path: str, min_severity: str = "low", limit: int = 30) -> str:
    """Ranked list of risky changes with reasons. Flags: destroy/replace of stateful resources
    (databases, buckets, disks, KMS keys, DNS zones, secrets; aws/azurerm/google/kubernetes plus
    generic name heuristics), which attribute forces a replacement, IAM wildcards and admin
    policies, security groups / firewalls opening 0.0.0.0/0 or ::/0 (admin and database ports
    rated highest), public access enabled, encryption disabled or key changed, deletion
    protection off, backup retention reduced. Tags-only updates are listed as low.

    min_severity: info | low | medium | high | critical. Only the findings are listed; resources
    not mentioned had nothing notable. Values of attributes are never printed here.
    """
    return analysis.risky_changes(loader.load(path), min_severity, limit)


@tool
def diff_resource(path: str, address: str, max_attributes: int = 200) -> str:
    """Attribute-level diff (before -> after) for one resource, with nested paths such as
    ingress[0].cidr_blocks[0]. Unknown values show as (known after apply). Sensitive values are
    ALWAYS shown as (sensitive): by Terraform's sensitivity masks and, as a second layer, by
    attribute names that look like credentials (password, secret, token, key...).

    address: exact address as in the plan, e.g. aws_instance.web["a b"] or module.net.aws_vpc.main[0].
    Use list_changes to find addresses; unknown addresses return close matches.
    """
    return analysis.diff_resource(loader.load(path), address, max_attributes)


@tool
def list_changes(
    path: str,
    action: str | None = None,
    type: str | None = None,
    module: str | None = None,
    address: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """List resource changes, filtered and capped.

    action: create | update | delete | replace | read | forget | no-op | import | move | other
            (default: everything except plain no-ops). type: glob such as aws_s3_*.
    module: 'root' or a module address prefix such as module.network (includes nested modules).
    address: glob where only * and ? are wild (brackets in addresses are literal).
    """
    return analysis.list_changes(loader.load(path), action, type, module, address, limit, offset)


@tool
def explain_replace(path: str, address: str) -> str:
    """Explain why a resource is being replaced: the action_reason, the forcing attribute(s)
    from replace_paths with their before -> after values, the order (destroy-then-create vs
    create_before_destroy), what that means (downtime, name collisions), the lifecycle hint from
    the plan's configuration when present, and the dependents that reference it.
    """
    return analysis.explain_replace(loader.load(path), address)


@tool
def compare_plans(path_a: str, path_b: str, limit: int = 50) -> str:
    """Compare two plans of the same configuration (for example before and after a code change,
    or two environments): resource changes new in B, gone in B, with a different action, or the
    same action but different planned values (shown as masked attribute diffs).
    """
    return analysis.compare_plans(loader.load(path_a), loader.load(path_b), limit)


@tool
def outputs_and_drift(path: str, limit: int = 50) -> str:
    """Output changes and resource_drift: what changed OUTSIDE Terraform (console edits, other
    tools) since the last apply, with masked attribute diffs. Sensitive outputs are masked.
    """
    return analysis.outputs_and_drift(loader.load(path), limit)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="tfplan-mcp", description="Read-only MCP server for Terraform plan review.")
    ap.add_argument("--dir", default=None, help="only plan files inside this directory can be read (default: current directory)")
    ap.add_argument("--max-mb", type=float, default=None,
                    help=f"largest plan file accepted, in MB (default {loader.DEFAULT_MAX_MB})")
    ap.add_argument("--version", action="version", version=f"tfplan-mcp {__version__}")
    args = ap.parse_args(argv)
    try:
        loader.configure(args.dir, args.max_mb)
    except PlanError as e:
        print(f"tfplan-mcp: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    mcp.run()


if __name__ == "__main__":
    main()
