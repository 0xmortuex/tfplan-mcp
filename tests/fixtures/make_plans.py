"""Regenerates tests/fixtures/plans/*.json: hand-shaped `terraform show -json` plans.

The shapes follow Terraform 1.5-1.9 (format_version 1.1 / 1.2). Run: python make_plans.py
"""

import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plans")
SECRET = "PLANTED-hunter2-SECRET-9f3a"


def rc(address, rtype, name, actions, before, after, *, unknown=None, bsens=None, asens=None,
       replace_paths=None, reason=None, module=None, index=None, mode="managed", **extra):
    d = {"address": address, "mode": mode, "type": rtype, "name": name,
         "provider_name": "registry.terraform.io/hashicorp/aws"}
    if module:
        d["module_address"] = module
    if index is not None:
        d["index"] = index
    d.update(extra)
    d["change"] = {
        "actions": actions, "before": before, "after": after,
        "after_unknown": unknown if unknown is not None else {},
        "before_sensitive": bsens if bsens is not None else ({} if before is not None else False),
        "after_sensitive": asens if asens is not None else {},
    }
    if replace_paths is not None:
        d["change"]["replace_paths"] = replace_paths
    if reason:
        d["action_reason"] = reason
    return d


def plan(changes, *, tf="1.9.5", fv="1.2", outputs=None, drift=None, config=None, **top):
    p = {"format_version": fv, "terraform_version": tf, "variables": {"db_password": {"value": SECRET}},
         "planned_values": {"root_module": {}}, "resource_changes": changes,
         "configuration": config or {"root_module": {}}}
    if outputs is not None:
        p["output_changes"] = outputs
    if drift is not None:
        p["resource_drift"] = drift
    p.update(top)
    return p


def write(name, obj):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    write("empty", plan([], fv="1.1", tf="1.5.7"))

    write("create_only", plan([
        rc("aws_vpc.main", "aws_vpc", "main", ["create"], None,
           {"cidr_block": "10.0.0.0/16", "tags": {"Name": "main"}}, unknown={"id": True, "arn": True}),
        rc("aws_subnet.a", "aws_subnet", "a", ["create"], None, {"cidr_block": "10.0.1.0/24"},
           unknown={"id": True, "vpc_id": True}),
    ], fv="1.1", tf="1.5.7"))

    write("in_place_update", plan([
        rc("aws_instance.web", "aws_instance", "web", ["update"],
           {"ami": "ami-1", "instance_type": "t3.micro", "tags": {"Name": "web"}},
           {"ami": "ami-1", "instance_type": "t3.small", "tags": {"Name": "web"}}),
        rc("aws_s3_bucket.logs", "aws_s3_bucket", "logs", ["update"],
           {"bucket": "logs", "tags": {"env": "dev"}, "tags_all": {"env": "dev"}},
           {"bucket": "logs", "tags": {"env": "prod"}, "tags_all": {"env": "prod"}}),
    ], fv="1.1", tf="1.6.0"))

    write("forced_replace", plan([
        rc("aws_db_instance.main", "aws_db_instance", "main", ["delete", "create"],
           {"engine": "postgres", "identifier": "main", "allocated_storage": 20},
           {"engine": "mysql", "identifier": "main", "allocated_storage": 20},
           replace_paths=[["engine"]], reason="replace_because_cannot_update"),
        rc("aws_instance.app", "aws_instance", "app", ["create", "delete"],
           {"ami": "ami-1", "subnet_id": "subnet-1"}, {"ami": "ami-2", "subnet_id": "subnet-1"},
           replace_paths=[["ami"]], reason="replace_because_cannot_update"),
        rc("aws_route53_record.db", "aws_route53_record", "db", ["update"],
           {"records": ["old.example.com"]}, {"records": []}, unknown={"records": True}),
    ], config={"root_module": {"resources": [
        {"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
         "expressions": {"engine": {"constant_value": "mysql"}}},
        {"address": "aws_route53_record.db", "mode": "managed", "type": "aws_route53_record", "name": "db",
         "expressions": {"records": {"references": ["aws_db_instance.main.address", "aws_db_instance.main"]}}},
    ], "outputs": {"db_host": {"expression": {"references": ["aws_db_instance.main.address", "aws_db_instance.main"]}}}}}))

    write("destroy_database", plan([
        rc("aws_db_instance.prod", "aws_db_instance", "prod", ["delete"],
           {"identifier": "prod", "engine": "postgres", "deletion_protection": False, "password": SECRET},
           None, bsens={"password": True}, reason="delete_because_no_resource_config"),
        rc("aws_s3_bucket.data", "aws_s3_bucket", "data", ["delete"], {"bucket": "data"}, None),
        rc("aws_kms_key.main", "aws_kms_key", "main", ["delete"], {"description": "k"}, None),
        rc("aws_security_group.old", "aws_security_group", "old", ["delete"], {"name": "old"}, None),
    ]))

    pol_before = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]})
    pol_after = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    write("iam_broadening", plan([
        rc("aws_iam_policy.app", "aws_iam_policy", "app", ["update"],
           {"name": "app", "policy": pol_before}, {"name": "app", "policy": pol_after}),
        rc("aws_iam_role_policy_attachment.admin", "aws_iam_role_policy_attachment", "admin", ["create"], None,
           {"role": "app", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        rc("aws_s3_bucket_policy.pub", "aws_s3_bucket_policy", "pub", ["create"], None,
           {"bucket": "b", "policy": json.dumps({"Statement": [
               {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]})}),
        rc("google_project_iam_member.pub", "google_project_iam_member", "pub", ["create"], None,
           {"role": "roles/viewer", "member": "allUsers"}),
    ]))

    write("sg_open", plan([
        rc("aws_security_group.web", "aws_security_group", "web", ["update"],
           {"name": "web", "ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp",
                                         "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}],
            "egress": [{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]},
           {"name": "web", "ingress": [
               {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []},
               {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []},
               {"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}],
            "egress": [{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]}),
        rc("aws_security_group_rule.all", "aws_security_group_rule", "all", ["create"], None,
           {"type": "ingress", "from_port": 0, "to_port": 65535, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}),
        rc("aws_security_group_rule.out", "aws_security_group_rule", "out", ["create"], None,
           {"type": "egress", "from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}),
        rc("google_compute_firewall.rdp", "google_compute_firewall", "rdp", ["create"], None,
           {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["3389"]}]}),
        rc("azurerm_network_security_rule.ssh", "azurerm_network_security_rule", "ssh", ["create"], None,
           {"direction": "Inbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "22"}),
    ]))

    write("sensitive", plan([
        rc("aws_db_instance.main", "aws_db_instance", "main", ["update"],
           {"identifier": "main", "password": SECRET + "-OLD", "master_token": SECRET + "-TOK",
            "settings": {"credentials": {"value": SECRET + "-NESTED"}, "size": 1},
            "tags": {"secret_key": SECRET + "-TAG", "Name": "m"}},
           {"identifier": "main", "password": SECRET + "-NEW", "master_token": SECRET + "-TOK2",
            "settings": {"credentials": {"value": SECRET + "-NESTED2"}, "size": 2},
            "tags": {"secret_key": SECRET + "-TAG2", "Name": "m"},
            "user_data": "postgres://admin:" + SECRET + "-URL@db.internal/app",
            "note": SECRET + "-FLAGGED-ONLY-BY-MASK"},
           bsens={"password": True, "settings": {"credentials": True}},
           asens={"password": True, "settings": {"credentials": True}, "note": True}),
        rc("aws_secretsmanager_secret_version.s", "aws_secretsmanager_secret_version", "s", ["create"], None,
           {"secret_string": SECRET + "-SV", "secret_id": "s"}, asens={"secret_string": True}),
    ], outputs={
        "db_password": {"actions": ["update"], "before": SECRET + "-O1", "after": SECRET + "-O2",
                        "after_unknown": False, "before_sensitive": True, "after_sensitive": True},
        "api_token": {"actions": ["create"], "before": None, "after": SECRET + "-O3",
                      "after_unknown": False, "before_sensitive": False, "after_sensitive": False},
    }))

    write("unknown_values", plan([
        rc("aws_instance.web", "aws_instance", "web", ["create"], None,
           {"ami": "ami-1", "tags": {"Name": "web"}, "root_block_device": [{"volume_size": 8}]},
           unknown={"id": True, "private_ip": True, "tags_all": {"Name": True}, "root_block_device": [{"volume_id": True}]}),
        rc("aws_eip.web", "aws_eip", "web", ["update"], {"instance": "i-old"}, {"instance": None},
           unknown={"instance": True}),
    ]))

    write("modules", plan([
        rc("module.network.aws_vpc.this", "aws_vpc", "this", ["create"], None, {"cidr_block": "10.0.0.0/16"},
           module="module.network"),
        rc('module.network.module.subnets["a"].aws_subnet.s', "aws_subnet", "s", ["create"], None,
           {"cidr_block": "10.0.1.0/24"}, module='module.network.module.subnets["a"]'),
        rc("aws_instance.root", "aws_instance", "root", ["update"], {"instance_type": "t3.micro"},
           {"instance_type": "t3.small"}),
    ]))

    write("count_foreach", plan([
        rc("aws_instance.n[0]", "aws_instance", "n", ["create"], None, {"ami": "a"}, index=0),
        rc("aws_instance.n[1]", "aws_instance", "n", ["create"], None, {"ami": "a"}, index=1),
        rc('aws_s3_bucket.b["my \\"quoted\\" key"]', "aws_s3_bucket", "b", ["create"], None, {"bucket": "q"},
           index='my "quoted" key'),
        rc('aws_s3_bucket.b["café-日本"]', "aws_s3_bucket", "b", ["delete"], {"bucket": "u"}, None,
           index="café-日本", reason="delete_because_each_key"),
        rc('aws_s3_bucket.b["a.b[c]"]', "aws_s3_bucket", "b", ["update"], {"force_destroy": False},
           {"force_destroy": True}, index="a.b[c]"),
    ]))

    write("drift", plan(
        [rc("aws_instance.web", "aws_instance", "web", ["update"], {"instance_type": "t3.small"},
            {"instance_type": "t3.micro"})],
        drift=[
            rc("aws_instance.web", "aws_instance", "web", ["update"], {"instance_type": "t3.micro", "tags": {"x": "1"}},
               {"instance_type": "t3.small", "tags": {"x": "2"}}),
            rc("aws_s3_bucket.gone", "aws_s3_bucket", "gone", ["delete"], {"bucket": "gone"}, None),
        ],
        outputs={"ip": {"actions": ["update"], "before": "1.1.1.1", "after": None, "after_unknown": True,
                        "before_sensitive": False, "after_sensitive": False}}))

    adopted = rc("aws_s3_bucket.adopted", "aws_s3_bucket", "adopted", ["no-op"], {"bucket": "adopted"},
                 {"bucket": "adopted"})
    adopted["change"]["importing"] = {"id": "adopted"}
    write("noop_moved_import", plan([
        rc("aws_instance.same", "aws_instance", "same", ["no-op"], {"ami": "a"}, {"ami": "a"}),
        rc("aws_instance.new_name", "aws_instance", "new_name", ["no-op"], {"ami": "a"}, {"ami": "a"},
           previous_address="aws_instance.old_name"),
        adopted,
        rc("aws_s3_bucket.forgotten", "aws_s3_bucket", "forgotten", ["forget"], {"bucket": "f"}, None),
    ], fv="1.2", tf="1.7.2"))

    write("errored_deferred", plan(
        [rc("aws_instance.web", "aws_instance", "web", ["create"], None, {"ami": "a"})],
        errored=True, applyable=False, complete=False,
        deferred_changes=[{"reason": "instance_count_unknown", "resource_change": rc(
            "aws_instance.later[0]", "aws_instance", "later", ["create"], None, {"ami": "a"})}],
        checks=[{"address": {"kind": "check", "name": "health"}, "status": "fail", "instances": []}]))

    write("exposure_misc", plan([
        rc("aws_s3_bucket_public_access_block.b", "aws_s3_bucket_public_access_block", "b", ["update"],
           {"block_public_acls": True, "block_public_policy": True},
           {"block_public_acls": False, "block_public_policy": True}),
        rc("aws_db_instance.pub", "aws_db_instance", "pub", ["update"],
           {"publicly_accessible": False, "storage_encrypted": True, "deletion_protection": True,
            "backup_retention_period": 14, "kms_key_id": "key-1"},
           {"publicly_accessible": True, "storage_encrypted": False, "deletion_protection": False,
            "backup_retention_period": 1, "kms_key_id": "key-2"}),
    ]))


main()
