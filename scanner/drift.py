"""Drift: things in AWS that no longer match what Terraform says, or that Terraform never knew about.

Input is the JSON from `terraform show -json`, so this works on a state file without running Terraform.
"""
from scanner.models import Finding


def state_resources(state):
    """Flatten the resources of the root module and any child modules."""
    def walk(module):
        for r in module.get("resources", []):
            yield r
        for child in module.get("child_modules", []):
            yield from walk(child)
    root = state.get("values", {}).get("root_module", {})
    return list(walk(root))


def _norm_state_ingress(rules):
    out = set()
    for r in rules or []:
        cidrs = tuple(sorted((r.get("cidr_blocks") or []) + (r.get("ipv6_cidr_blocks") or [])))
        proto = "-1" if r.get("protocol") in ("-1", -1) else r.get("protocol")
        out.add((proto, r.get("from_port", 0), r.get("to_port", 0), cidrs))
    return out


def _norm_live_ingress(perms):
    out = set()
    for p in perms:
        cidrs = tuple(sorted([x["CidrIp"] for x in p.get("IpRanges", [])]
                             + [x["CidrIpv6"] for x in p.get("Ipv6Ranges", [])]))
        proto = p["IpProtocol"]
        out.add((proto, p.get("FromPort", 0), p.get("ToPort", 0), cidrs))
    return out


def _drift(rid, what, expected, actual):
    return Finding("DRIFT", "high", rid,
                   f"{what} changed outside Terraform. Terraform says {expected}, AWS has {actual}.",
                   "Run terraform plan. Either apply to put it back, or update the code if the change was intended.",
                   kind="drift")


def check_drift(session, state):
    ec2 = session.client("ec2")
    s3 = session.client("s3")
    resources = state_resources(state)
    findings = []

    live_sgs = {g["GroupId"]: g for g in ec2.describe_security_groups()["SecurityGroups"]}
    live_vols = {v["VolumeId"]: v for v in ec2.describe_volumes()["Volumes"]}
    live_instances = {i["InstanceId"]: i for r in ec2.describe_instances()["Reservations"]
                      for i in r["Instances"] if i["State"]["Name"] != "terminated"}
    live_buckets = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}

    known = {"sg": set(), "vol": set(), "inst": set(), "bucket": set()}

    for r in resources:
        v = r.get("values", {})
        rid = v.get("id")
        t = r["type"]
        if t == "aws_security_group":
            known["sg"].add(rid)
            live = live_sgs.get(rid)
            if live is None:
                findings.append(Finding("DRIFT", "high", rid, "Security group was deleted outside Terraform.",
                                        "Run terraform apply to recreate it.", kind="drift"))
            elif _norm_state_ingress(v.get("ingress")) != _norm_live_ingress(live["IpPermissions"]):
                findings.append(_drift(rid, "Inbound rules",
                                       sorted(_norm_state_ingress(v.get("ingress"))),
                                       sorted(_norm_live_ingress(live["IpPermissions"]))))
        elif t == "aws_ebs_volume":
            known["vol"].add(rid)
            live = live_vols.get(rid)
            if live is None:
                findings.append(Finding("DRIFT", "high", rid, "Volume was deleted outside Terraform.",
                                        "Run terraform apply to recreate it.", kind="drift"))
            else:
                if live["Size"] != v.get("size"):
                    findings.append(_drift(rid, "Volume size", v.get("size"), live["Size"]))
                if bool(live.get("Encrypted")) != bool(v.get("encrypted")):
                    findings.append(_drift(rid, "Volume encryption", v.get("encrypted"), live.get("Encrypted")))
        elif t == "aws_instance":
            known["inst"].add(rid)
            live = live_instances.get(rid)
            if live is None:
                findings.append(Finding("DRIFT", "high", rid, "Instance was deleted outside Terraform.",
                                        "Run terraform apply to recreate it.", kind="drift"))
            elif live["InstanceType"] != v.get("instance_type"):
                findings.append(_drift(rid, "Instance type", v.get("instance_type"), live["InstanceType"]))
        elif t == "aws_s3_bucket":
            name = v.get("bucket") or rid
            known["bucket"].add(name)
            if name not in live_buckets:
                findings.append(Finding("DRIFT", "high", name, "Bucket was deleted outside Terraform.",
                                        "Run terraform apply to recreate it.", kind="drift"))
        elif t == "aws_s3_bucket_versioning":
            name = v.get("bucket")
            if name in live_buckets:
                want = (v.get("versioning_configuration") or [{}])[0].get("status")
                have = s3.get_bucket_versioning(Bucket=name).get("Status", "Disabled")
                if want != have:
                    findings.append(_drift(name, "Bucket versioning", want, have))

    # Things that exist in AWS but Terraform has never heard of.
    for gid, g in live_sgs.items():
        if g["GroupName"] != "default" and gid not in known["sg"]:
            findings.append(Finding("DRIFT-UNTRACKED", "medium", gid,
                                    f"Security group {g['GroupName']} exists in AWS but not in Terraform.",
                                    "Import it into Terraform or delete it if nobody needs it.", kind="drift"))
    for vid in live_vols:
        if vid not in known["vol"]:
            findings.append(Finding("DRIFT-UNTRACKED", "medium", vid, "Volume exists in AWS but not in Terraform.",
                                    "Import it into Terraform or delete it if nobody needs it.", kind="drift"))
    for iid in live_instances:
        if iid not in known["inst"]:
            findings.append(Finding("DRIFT-UNTRACKED", "medium", iid, "Instance exists in AWS but not in Terraform.",
                                    "Import it into Terraform or terminate it if nobody needs it.", kind="drift"))
    for name in live_buckets:
        if name not in known["bucket"]:
            findings.append(Finding("DRIFT-UNTRACKED", "medium", name, "Bucket exists in AWS but not in Terraform.",
                                    "Import it into Terraform or delete it if nobody needs it.", kind="drift"))
    return findings
