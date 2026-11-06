"""Risk heuristics for plan changes.

Findings are built from fixed strings plus resource addresses, attribute names and
network ranges/ports only. Attribute VALUES (which may be secrets) are compared here
but never copied into a finding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .diff import diff_change, fmt_replace_path
from .loader import Change

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SCORE = {s: i for i, s in enumerate(SEVERITIES)}

# (regex on resource type, category, base severity when destroyed/replaced)
_STATEFUL: list[tuple[str, str, str]] = [
    # aws
    (r"^aws_(db_instance|rds_cluster|rds_cluster_instance|rds_global_cluster|docdb_cluster|neptune_cluster|"
     r"redshift_cluster|elasticache_replication_group|elasticache_cluster|memorydb_cluster|"
     r"dynamodb_table|keyspaces_table|timestreamwrite_table|qldb_ledger|opensearch_domain|elasticsearch_domain|"
     r"dax_cluster|mq_broker|msk_cluster|kinesis_stream|dms_replication_instance)$", "database/datastore", "critical"),
    (r"^aws_(s3_bucket|s3_directory_bucket|glacier_vault|efs_file_system|fsx_.*|ebs_volume|backup_vault|ecr_repository)$",
     "storage", "critical"),
    (r"^aws_(kms_key|kms_external_key|kms_replica_key|cloudhsm_v2_cluster|acmpca_certificate_authority)$", "key material", "critical"),
    (r"^aws_(route53_zone|route53_delegation_set|route53_hosted_zone_dnssec)$", "DNS zone", "critical"),
    (r"^aws_(secretsmanager_secret|ssm_parameter|cognito_user_pool|cloudwatch_log_group|iam_user|eip|"
     r"lb|alb|elb|ecs_cluster|eks_cluster|vpc|subnet|instance)$", "stateful or identity-bearing", "high"),
    # azurerm
    (r"^azurerm_(mssql_database|mssql_server|mssql_managed_instance|sql_database|sql_server|postgresql_.*server|"
     r"postgresql_database|mysql_.*server|mysql_database|mariadb_.*|cosmosdb_.*|redis_cache|synapse_.*|"
     r"data_factory|kusto_cluster|kusto_database|databricks_workspace)$", "database/datastore", "critical"),
    (r"^azurerm_(storage_account|storage_container|managed_disk|netapp_.*|backup_.*|recovery_services_vault|"
     r"data_lake_store)$", "storage", "critical"),
    (r"^azurerm_(key_vault|key_vault_key|key_vault_secret|key_vault_managed_hardware_security_module)$", "key material", "critical"),
    (r"^azurerm_(dns_zone|private_dns_zone)$", "DNS zone", "critical"),
    (r"^azurerm_(kubernetes_cluster|virtual_network|public_ip|application_gateway|container_registry)$",
     "stateful or identity-bearing", "high"),
    # google
    (r"^google_(sql_database_instance|sql_database|spanner_instance|spanner_database|bigtable_instance|"
     r"bigquery_dataset|bigquery_table|firestore_database|redis_instance|alloydb_.*|memcache_instance|"
     r"datastore_index|firebase_.*database.*)$", "database/datastore", "critical"),
    (r"^google_(storage_bucket|compute_disk|compute_region_disk|filestore_instance|compute_snapshot)$", "storage", "critical"),
    (r"^google_(kms_crypto_key|kms_key_ring|kms_crypto_key_version)$", "key material", "critical"),
    (r"^google_(dns_managed_zone)$", "DNS zone", "critical"),
    (r"^google_(secret_manager_secret|container_cluster|compute_address|pubsub_topic|compute_instance)$",
     "stateful or identity-bearing", "high"),
    # kubernetes
    (r"^kubernetes_(persistent_volume|persistent_volume_claim|persistent_volume_v1|persistent_volume_claim_v1|"
     r"stateful_set|stateful_set_v1)$", "storage", "critical"),
    (r"^kubernetes_(namespace|namespace_v1|secret|secret_v1|storage_class|storage_class_v1)$",
     "stateful or identity-bearing", "high"),
]
_STATEFUL_RE = [(re.compile(p), c, s) for p, c, s in _STATEFUL]
_GENERIC = re.compile(
    r"(database|_db(_|$)|bucket|volume|disk|snapshot|backup|kms|vault|zone|storage|cluster|"
    r"datastore|table$|keyring|key_ring|secret|cache|queue|topic|registry)"
)

TAG_ATTRS = {"tags", "tags_all", "labels", "tag", "terraform_labels", "effective_labels", "default_tags"}

_PUBLIC_TRUE = {
    "publicly_accessible", "public_network_access_enabled", "allow_blob_public_access",
    "allow_nested_items_to_be_public", "public_access", "enable_public_ip", "associate_public_ip_address_enabled",
    "ipv4_enabled", "enable_public_network_access", "anonymous_access_enabled", "public_read_access",
}
_PUBLIC_BLOCK_FALSE = {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
_ENC_FALSE = {
    "encrypted", "storage_encrypted", "encryption_enabled", "enable_encryption", "at_rest_encryption_enabled",
    "transit_encryption_enabled", "enable_https_traffic_only", "https_traffic_only_enabled",
    "infrastructure_encryption_enabled", "require_secure_transfer", "ssl_enforcement_enabled",
    "ssl_enforcement", "kms_encrypted", "encrypt_at_rest", "node_to_node_encryption",
}
_KEY_ATTRS = {
    "kms_key_id", "kms_master_key_id", "kms_key_arn", "kms_key_name", "key_vault_key_id",
    "customer_managed_key_id", "disk_encryption_set_id", "encryption_key", "kms_key_self_link",
    "default_kms_key_name",
}
_DELPROT = {"deletion_protection", "deletion_protection_enabled", "enable_deletion_protection",
            "delete_protection", "deletion_protection_policy", "prevent_destroy", "purge_protection_enabled"}
_RETENTION = {"backup_retention_period", "backup_retention_days", "retention_in_days", "retention_days",
              "backup_retention", "retained_backups", "retention_period", "point_in_time_recovery_retention"}

ADMIN_PORTS = {22: "SSH", 23: "telnet", 135: "RPC", 445: "SMB", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
DATA_PORTS = {
    1433: "SQL Server", 1521: "Oracle", 2181: "ZooKeeper", 2375: "Docker API", 2379: "etcd", 3306: "MySQL",
    5432: "PostgreSQL", 5601: "Kibana", 6379: "Redis", 8500: "Consul", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 10250: "kubelet",
}
_OPEN_V4 = {"0.0.0.0/0", "0.0.0.0", "*", "internet", "any", "<nw>/0"}
_OPEN_V6 = {"::/0"}


@dataclass
class Finding:
    severity: str
    text: str


def stateful_info(rtype: str) -> tuple[str, str] | None:
    for rx, cat, sev in _STATEFUL_RE:
        if rx.match(rtype):
            return cat, sev
    if _GENERIC.search(rtype):
        return "looks stateful (generic name heuristic)", "medium"
    return None


# ---------------------------------------------------------------- flatten helpers

Leaf = tuple[tuple[str | int, ...], Any]


def leaves(v: Any, path: tuple[str | int, ...] = (), depth: int = 0) -> list[Leaf]:
    out: list[Leaf] = []
    stack: list[tuple[Any, tuple[str | int, ...], int]] = [(v, path, depth)]
    while stack and len(out) < 20000:
        cur, p, d = stack.pop()
        if isinstance(cur, dict) and d < 40:
            for k, x in cur.items():
                stack.append((x, (*p, k), d + 1))
        elif isinstance(cur, list) and d < 40:
            for i, x in enumerate(cur):
                stack.append((x, (*p, i), d + 1))
        else:
            out.append((p, cur))
    return out


def _leaf_map(v: Any) -> dict[tuple[str | int, ...], Any]:
    return dict(leaves(v))


def _name(path: tuple[str | int, ...]) -> str:
    for p in reversed(path):
        if isinstance(p, str):
            return p
    return ""


def _fmt(path: tuple[str | int, ...]) -> str:
    return ".".join(str(p) for p in path)


# ---------------------------------------------------------------- IAM

def _as_list(x: Any) -> list[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _policy_docs(values: Any) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for _, val in leaves(values):
        if isinstance(val, str) and len(val) < 2_000_000 and '"Statement"' in val and val.lstrip()[:1] == "{":
            try:
                d = json.loads(val)
            except (ValueError, RecursionError):
                continue
            if isinstance(d, dict):
                docs.append(d)
    if isinstance(values, dict):
        for k in ("policy", "assume_role_policy", "policy_document"):
            if isinstance(values.get(k), dict) and "Statement" in values[k]:
                docs.append(values[k])
    return docs


def _iam_flags(values: Any) -> set[str]:
    flags: set[str] = set()
    for doc in _policy_docs(values):
        for st in _as_list(doc.get("Statement")):
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            acts = [a for a in _as_list(st.get("Action")) if isinstance(a, str)]
            res = [r for r in _as_list(st.get("Resource")) if isinstance(r, str)]
            pr = st.get("Principal")
            princ: list[Any] = []
            if isinstance(pr, dict):
                for x in pr.values():
                    princ += _as_list(x)
            else:
                princ = _as_list(pr)
            act_star = "*" in acts
            svc_star = any(a.endswith(":*") for a in acts)
            res_star = "*" in res
            if act_star and res_star:
                flags.add("admin")
            elif act_star:
                flags.add("action_star")
            elif svc_star and res_star:
                flags.add("service_star")
            if "*" in princ and "Condition" not in st:
                flags.add("principal_star")
    return flags


_IAM_TEXT = {
    "admin": ("critical", "IAM policy grants Action '*' on Resource '*' (full administrator access)"),
    "action_star": ("high", "IAM policy allows Action '*' (every API action) on the listed resources"),
    "service_star": ("high", "IAM policy allows a whole service ('service:*') on Resource '*'"),
    "principal_star": ("high", "policy allows Principal '*' (anyone, including other AWS accounts / the public)"),
}
_BROAD_VALUES = ("/AdministratorAccess", "/IAMFullAccess", "/PowerUserAccess")


def _iam_findings(b: Any, a: Any) -> list[Finding]:
    out: list[Finding] = []
    new = _iam_flags(a) - _iam_flags(b)
    for f in ("admin", "action_star", "service_star", "principal_star"):
        if f in new:
            sev, txt = _IAM_TEXT[f]
            out.append(Finding(sev, txt))
    before_vals = {v for _, v in leaves(b) if isinstance(v, str)}
    for path, v in leaves(a):
        if not isinstance(v, str) or v in before_vals:
            continue
        n = _name(path)
        if v.endswith(_BROAD_VALUES) and v.startswith("arn:"):
            out.append(Finding("high", f"attaches a broad managed policy ({v.rsplit('/', 1)[-1]}) via {n}"))
        elif n in ("role", "role_id") and v in ("roles/owner", "roles/editor"):
            out.append(Finding("high", f"grants the primitive GCP role {v}"))
        elif n in ("member", "members") and v in ("allUsers", "allAuthenticatedUsers"):
            out.append(Finding("critical", f"grants access to {v} (the public internet)"))
        elif n == "role_definition_name" and v in ("Owner", "Contributor", "User Access Administrator"):
            out.append(Finding("high" if v != "Contributor" else "medium", f"assigns the Azure role {v}"))
    return out


# ---------------------------------------------------------------- network exposure

def _ports_of(rule: dict[str, Any]) -> list[tuple[int, int]] | None:
    """Port ranges a rule dict covers; None means all."""
    proto = rule.get("protocol", rule.get("ip_protocol"))
    if str(proto) in ("-1", "all", "*", "-1.0"):
        return None
    if "from_port" in rule or "to_port" in rule:
        try:
            lo = int(rule.get("from_port") or 0)
            tp = rule.get("to_port")
            hi = int(tp) if tp is not None else lo
        except (TypeError, ValueError):
            return None
        if lo == 0 and hi in (0, 65535) and str(proto).lower() not in ("icmp", "1"):
            return None
        return [(lo, hi)]
    ranges: list[tuple[int, int]] = []
    found = False
    for key in ("destination_port_range", "destination_port_ranges", "ports"):
        for p in _as_list(rule.get(key)):
            found = True
            s = str(p).strip()
            if s in ("*", ""):
                return None
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", s)
            if m:
                ranges.append((int(m.group(1)), int(m.group(2) or m.group(1))))
    return ranges if found else None


def _open_rules(rtype: str, values: Any) -> set[tuple[str, int, int]]:
    """Set of (cidr, lo, hi) for ingress rules open to the world. (0,65535) = all ports."""
    out: set[tuple[str, int, int]] = set()
    stack: list[tuple[Any, bool, int]] = [(values, False, 0)]
    if "egress" in rtype:
        return out
    while stack:
        cur, egress, d = stack.pop()
        if d > 30:
            continue
        if isinstance(cur, list):
            stack += [(x, egress, d + 1) for x in cur]
        elif isinstance(cur, dict):
            for k, x in cur.items():
                stack.append((x, egress or k == "egress", d + 1))
            if egress:
                continue
            if cur.get("type") == "egress" or cur.get("egress") is True:
                continue
            if str(cur.get("direction", "")).lower() in ("outbound", "egress"):
                continue
            if str(cur.get("access", "allow")).lower() == "deny" or str(cur.get("rule_action", "allow")).lower() == "deny":
                continue
            srcs: list[str] = []
            for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6", "cidr_block", "ipv6_cidr_block",
                        "source_address_prefix", "source_address_prefixes", "source_ranges"):
                srcs += [str(s) for s in _as_list(cur.get(key)) if isinstance(s, str)]
            hits = [s for s in srcs if s.lower() in _OPEN_V4 or s in _OPEN_V6]
            if not hits:
                continue
            if "allow" in cur and isinstance(cur["allow"], list):  # google_compute_firewall
                for al in cur["allow"]:
                    if isinstance(al, dict):
                        pr = _ports_of(al)
                        for h in hits:
                            for lo, hi in (pr if pr is not None else [(0, 65535)]):
                                out.add((h, lo, hi))
                continue
            pr = _ports_of(cur)
            for h in hits:
                for lo, hi in (pr if pr is not None else [(0, 65535)]):
                    out.add((h, lo, hi))
    return out


def _network_findings(rtype: str, b: Any, a: Any) -> list[Finding]:
    new = _open_rules(rtype, a) - _open_rules(rtype, b)
    out: list[Finding] = []
    for cidr, lo, hi in sorted(new):
        rng = "ALL ports" if (lo, hi) == (0, 65535) else (f"port {lo}" if lo == hi else f"ports {lo}-{hi}")
        admin = sorted(f"{p}/{n}" for p, n in ADMIN_PORTS.items() if lo <= p <= hi)
        data = sorted(f"{p}/{n}" for p, n in DATA_PORTS.items() if lo <= p <= hi)
        src = "the whole internet" if cidr in ("0.0.0.0/0", "::/0") else f"'{cidr}' (any source)"
        if (lo, hi) == (0, 65535):
            out.append(Finding("critical", f"opens ALL ports to {src}"))
        elif admin:
            out.append(Finding("critical", f"opens {rng} to {src}, including admin port(s) {', '.join(admin)}"))
        elif data:
            out.append(Finding("high", f"opens {rng} to {src}, including data-service port(s) {', '.join(data)}"))
        elif (lo, hi) in ((80, 80), (443, 443), (80, 443)):
            continue
        else:
            out.append(Finding("medium", f"opens {rng} to {src}"))
    return out


# ---------------------------------------------------------------- attribute rules

def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _attr_findings(b: Any, a: Any, creating: bool) -> list[Finding]:
    out: list[Finding] = []
    bm, am = _leaf_map(b), _leaf_map(a)
    seen: set[str] = set()

    def add(sev: str, txt: str) -> None:
        if txt not in seen:
            seen.add(txt)
            out.append(Finding(sev, txt))

    for path, av in am.items():
        n = _name(path)
        bv = bm.get(path)
        where = _fmt(path)
        if n in _PUBLIC_TRUE and av is True and bv is not True:
            add("high", f"public access enabled ({where} = true)")
        elif n in _PUBLIC_BLOCK_FALSE and av is False and bv is not False:
            add("high", f"public access block weakened ({where} = false)")
        elif n in ("acl", "predefined_acl", "default_acl") and av in ("public-read", "public-read-write", "publicRead", "publicReadWrite") and bv != av:
            add("high", f"bucket ACL made public ({where})")
        elif n in _ENC_FALSE and av is False and bv is not False:
            add("high", f"encryption/secure transport disabled ({where} = false)")
        elif n == "enable_key_rotation" and av is False and bv is not False:
            add("medium", f"key rotation disabled ({where})")
        elif n in _KEY_ATTRS and path in bm and bv not in (None, "") and bv != av:
            if av in (None, ""):
                add("high", f"encryption key removed ({where})")
            else:
                add("medium", f"encryption key changed ({where}); data is re-encrypted or the resource is replaced")
        elif n in _DELPROT and av is False and bv is True:
            add("high", f"deletion protection turned off ({where})")
        elif n in _RETENTION:
            x, y = _num(bv), _num(av)
            if x is not None and y is not None and y < x:
                add("high" if y == 0 else "medium", f"retention reduced ({where}: {x:g} -> {y:g})")
        elif n == "skip_final_snapshot" and av is True and bv is not True:
            add("medium", f"final snapshot skipped on delete ({where} = true)")
        elif n == "force_destroy" and av is True and bv is not True:
            add("medium", f"force_destroy enabled ({where}): non-empty bucket/zone can be destroyed")
        elif n in ("versioning_enabled", "enable_versioning") and av is False and bv is True:
            add("medium", f"versioning disabled ({where})")
        elif n == "multi_az" and av is False and bv is True:
            add("medium", f"multi-AZ turned off ({where})")
    for path, bv in bm.items():  # attributes that disappeared
        n = _name(path)
        if path not in am and n in _DELPROT and bv is True and not creating:
            add("high", f"deletion protection removed ({_fmt(path)})")
    return out


# ---------------------------------------------------------------- per-change assessment

@dataclass
class Assessment:
    change: Change
    severity: str
    reasons: list[str]
    tags_only: bool = False


def assess(c: Change) -> Assessment | None:
    """Findings for one resource change, or None if there is nothing worth reporting."""
    if c.kind in ("no-op", "read"):
        return None
    ch = c.change
    before, after = ch.get("before"), ch.get("after")
    findings: list[Finding] = []
    info = stateful_info(c.type)
    if c.kind in ("delete", "replace", "forget"):
        word = {"delete": "destroyed", "replace": "replaced (destroy + create)", "forget": "removed from state"}[c.kind]
        if c.kind == "forget":
            findings.append(Finding("medium", "removed from state without destroying (terraform forgets it; the real object stays unmanaged)"))
        elif info:
            cat, sev = info
            if c.kind == "replace" and sev == "critical" and c.order == "create_then_delete":
                sev = "high"
            if c.kind == "replace" and sev == "high":
                sev = "medium" if "generic" not in cat else sev
            findings.append(Finding(sev, f"{cat} resource {c.type} will be {word}"
                                         + (": data held by it is lost" if sev in ("critical", "high") and c.kind == "delete" else "")))
        else:
            findings.append(Finding("medium" if c.kind == "delete" else "low", f"{c.type or 'resource'} will be {word}"))
        if c.kind == "replace":
            rp = ch.get("replace_paths")
            if isinstance(rp, list) and rp:
                paths = ", ".join(fmt_replace_path(p) for p in rp[:6])
                findings.append(Finding("info", f"forced by change to: {paths}"))
            if c.reason:
                findings.append(Finding("info", f"action_reason: {c.reason}"))
        elif c.reason:
            findings.append(Finding("info", f"action_reason: {c.reason}"))
    new_state = after if c.kind != "delete" else None
    old_state = before if c.kind != "create" else None
    if c.kind != "delete" and c.kind != "forget":
        t = c.type
        findings += _attr_findings(old_state, new_state, c.kind == "create")
        if "iam" in t or "policy" in t or "role" in t or "bucket_policy" in t or "assume" in t or t.startswith("azurerm_role"):
            findings += _iam_findings(old_state, new_state)
        if any(x in t for x in ("security_group", "firewall", "network_acl", "nsg", "network_security")):
            findings += _network_findings(t, old_state, new_state)
        elif t.endswith("_rule") or "ingress" in t:
            findings += _network_findings(t, old_state, new_state)
    tags_only = False
    if c.kind == "update" and not any(f.severity != "info" for f in findings):
        ents, _ = diff_change(ch, limit=500)
        tops = {e.top for e in ents}
        if tops and tops <= TAG_ATTRS:
            tags_only = True
            findings.append(Finding("low", "tags/labels-only change"))
    if not findings:
        return None
    worst = max(findings, key=lambda f: SCORE[f.severity]).severity
    seen: set[str] = set()
    reasons = []
    for f in sorted(findings, key=lambda f: -SCORE[f.severity]):
        if f.text not in seen:
            seen.add(f.text)
            reasons.append(f"[{f.severity}] {f.text}")
    return Assessment(c, worst, reasons, tags_only)
