# tfplan-mcp

**Let your AI agent risk-review a Terraform / OpenTofu plan, without ever touching your cloud.**

<!-- mcp-name: io.github.0xmortuex/tfplan-mcp -->

tfplan-mcp is an [MCP](https://modelcontextprotocol.io) server that reads the JSON from
`terraform show -json tfplan` (or `tofu show -json`) and answers the questions you ask before
`apply`: what is being destroyed, what is being replaced and why, did an IAM policy just get
broader, is something now open to `0.0.0.0/0`, what changed outside Terraform.

**What is different about it.** Other plan-review MCP servers exist (for example
[tfmcp](https://github.com/nwiizo/tfmcp), which also runs terraform for you, and
`tf-review-mcp` / `cloud-devops-mcp-server`, which return findings). This one is built around
two things:

1. **It is a plan *reader*, not a runner.** It never executes terraform/tofu, never contacts a
   provider or cloud, depends only on the `mcp` package, and can be fenced into one directory
   with `--dir`.
2. **Two-layer secret masking.** Values Terraform marks sensitive (`before_sensitive` /
   `after_sensitive`) and values whose *names* look like credentials (`password`, `token`,
   `secret`, `key`...) are always printed as `(sensitive)`, even when the plan did not flag
   them. Findings only ever contain addresses, attribute names and network ranges, never
   attribute values. It also gives you attribute-level diffs, `replace_paths` explanations,
   dependents, and a two-plan comparison, not only a score.

## Install

Claude Code:

```
claude mcp add tfplan -- uvx tfplan-mcp --dir /path/to/your/plans
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tfplan": {
      "command": "uvx",
      "args": ["tfplan-mcp", "--dir", "C:\\Users\\you\\infra\\plans"]
    }
  }
}
```

Make a plan file first:

```
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

## Tools

| Tool | What it does |
| --- | --- |
| `plan_summary` | Counts of create/update/delete/replace/read/forget/no-op by resource type and module; empty or destroy plan; moved/imported; drift; output changes; failing checks; terraform version; warnings (errored, incomplete, deferred). |
| `risky_changes` | Ranked findings with reasons: destroy/replace of databases, buckets, disks, KMS keys, DNS zones; which attribute forced a replacement; IAM `*` and AdministratorAccess; `0.0.0.0/0` / `::/0` on admin and database ports; public access on; encryption off or key changed; deletion protection off; backup retention cut. Tags-only changes are demoted to low. |
| `diff_resource` | Attribute-level `before -> after` with nested paths, `(known after apply)`, and masked secrets. |
| `list_changes` | Filter by action, type glob, module, address glob; capped and paged. |
| `explain_replace` | Why it is replaced (`action_reason`, `replace_paths` with values), destroy-then-create vs create-before-destroy, lifecycle hint, dependents. |
| `compare_plans` | Two plans of the same config: new, removed, different action, different planned values. |
| `outputs_and_drift` | Output changes and `resource_drift` (changed outside Terraform). |

## Try asking

- "Summarize `plan.json`. Is anything being destroyed?"
- "What are the riskiest changes in `plan.json`? Rank them."
- "Why is `aws_db_instance.main` being replaced, and what depends on it?"
- "Show me exactly what changes on `module.network.aws_security_group.web`."
- "Did anyone change anything outside Terraform? (check drift)"
- "Compare `plan-before.json` and `plan-after.json`: what did my refactor change?"
- "List every deleted resource under `module.legacy`."

## Limits and behaviour

- **Size:** plan files up to **256 MB** are accepted by default (`--max-mb N` changes it). Bigger
  files are refused with a clear message. The file is read once and parsed in one pass; expect
  roughly 5-10x the file size in RAM. The last two parsed plans are cached.
- **Input checks:** a state file (`terraform show -json` of a state), a raw `.tfstate`, a binary
  `tfplan`, or the streaming log of `terraform plan -json` each get a specific explanation of what
  to run instead. `NaN`/`Infinity` are rejected; integers over 1000 digits are shown as
  "(huge integer)"; absurd nesting is a clean error.
- **Understands:** `format_version` 1.x (Terraform 1.5 to 1.9, OpenTofu), `count`/`for_each`
  addresses with quotes, brackets and unicode, nested modules, `moved`/`import`/`forget`
  (no-op with `previous_address` / `importing`), `deferred_changes`, `errored`, empty plans.
- **Heuristics are heuristics.** The risk table covers common aws/azurerm/google/kubernetes
  types plus generic name patterns. It will miss things and over-flag a few. Read the diff for
  anything that matters.
- The plan JSON does not record `lifecycle` settings, so `create_before_destroy` is inferred
  from the action order.

## Security

- **Read-only.** No terraform/tofu execution, no network, no provider calls, nothing is written.
- **Sandbox.** Only files under `--dir` (default: the working directory) can be read. Paths are
  resolved with symlinks followed, and anything outside is refused.
- **Secrets.** Terraform's own sensitivity masks and a name heuristic are both applied before any
  value is shown; connection-string passwords, private key blocks, cloud access key ids and JWTs
  are scrubbed from displayed strings. The plan's top-level `variables` and `generated_config`
  are never printed. Heuristics can over-mask (a `secret_id` is masked) which is the safe side;
  a secret stored under an innocuous name *inside a larger string* (for example inside a JSON
  policy document) is shown as part of that string, so treat plan output like the plan file.
- A plan contains real infrastructure details. Anything an agent reads goes to your model
  provider: only point it at plans you are willing to share with it.

## Development

```
uv sync --extra test
uv run pytest tests
uv run ruff check src tests
uv run mypy --strict src
```

The fixtures in `tests/fixtures/plans` are generated by `tests/fixtures/make_plans.py`
(hand-shaped Terraform 1.5-1.9 plans). An optional test that makes a real plan with a local
binary (`terraform_data` only, no provider download) runs with `TFPLAN_REAL_TERRAFORM=1`.

Want to build it yourself? See [tfplan-mcp-the-hard-way](https://github.com/0xmortuex/tfplan-mcp-the-hard-way).

MIT licensed.
