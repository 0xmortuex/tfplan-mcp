# Changelog

## 0.1.0 - 2026-11-06

First release.

- Seven read-only tools: `plan_summary`, `risky_changes`, `diff_resource`, `list_changes`,
  `explain_replace`, `compare_plans`, `outputs_and_drift`.
- Input: `terraform show -json` of a plan, format_version 1.x (Terraform 1.5-1.9, OpenTofu).
  Detects and explains state files, raw tfstate, binary plans and `plan -json` logs.
- Two-layer secret masking (Terraform sensitivity masks + name heuristics, plus value-shape scrubbing).
- `--dir` sandbox and `--max-mb` size cap (default 256 MB).
