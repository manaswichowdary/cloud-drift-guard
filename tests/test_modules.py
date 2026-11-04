import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from scanner import alerts, cost, drift, fixes, github_pr
from scanner.models import Finding
from scanner.runner import run_all
from scanner.store import Store


# ---------- runner ----------
def test_a_broken_rule_does_not_hide_the_others(session):
    def boom(_):
        raise RuntimeError("no permission")
    def ok(_):
        return [Finding("X", "low", "r", "m", "f")]
    findings, errors = run_all(session, rules=(boom, ok))
    assert len(findings) == 1 and errors[0]["rule"] == "boom"


# ---------- store: alert only on new ----------
def test_store_reports_only_new_and_resolved():
    s = Store()
    f1 = Finding("A", "high", "r1", "m", "f")
    f2 = Finding("B", "low", "r2", "m", "f")
    new, resolved = s.record([f1, f2])
    assert len(new) == 2 and resolved == []
    new, resolved = s.record([f1])            # f2 fixed
    assert new == [] and resolved == [("B", "r2")]
    new, _ = s.record([f1, f2])               # f2 came back
    assert [f.rule_id for f in new] == ["B"]


# ---------- cost ----------
def test_spend_jump_detected():
    days = [2.0] * 7 + [5.0] * 7
    f = cost.spend_jump(days)
    assert f and f.rule_id == "COST-JUMP"


def test_small_spend_is_ignored():
    assert cost.spend_jump([0.02] * 7 + [0.20] * 7) is None


def test_steady_spend_ignored_and_short_history_ignored():
    assert cost.spend_jump([3.0] * 14) is None
    assert cost.spend_jump([3.0] * 5) is None


def test_monthly_waste_sums_only_waste(session):
    fs = [Finding("A", "low", "x", "m", "f", kind="waste", monthly_usd=3.65),
          Finding("B", "low", "y", "m", "f", kind="waste", monthly_usd=0.64),
          Finding("C", "high", "z", "m", "f", monthly_usd=99)]
    assert cost.monthly_waste(fs) == 4.29


# ---------- alerts ----------
def test_alert_is_capped_and_sorted_high_first():
    fs = [Finding(f"R{i}", "low", f"r{i}", "m", "f") for i in range(15)]
    fs.append(Finding("TOP", "high", "z", "m", "f"))
    text = alerts.format_slack(fs)["text"]
    lines = text.split("\n")
    assert "[high]" in lines[1]
    assert len(lines) == 1 + alerts.MAX_LINES + 1  # header, capped lines, "and N more"
    assert "6 more" in lines[-1]


def test_no_findings_means_no_message():
    assert alerts.format_slack([]) is None


def test_send_slack_posts_json():
    post = MagicMock()
    alerts.send_slack("https://hooks.example/x", {"text": "hi"}, post=post)
    post.assert_called_once()
    assert post.call_args.kwargs["json"] == {"text": "hi"}


# ---------- fixes ----------
def test_only_three_rules_are_safe():
    safe = [r for r in ("S3-VERSIONING", "S3-PUBLIC", "ACCT-NO-PW-POLICY", "SG-SSH-OPEN",
                        "EBS-UNATTACHED", "IAM-OLD-KEY") if fixes.propose(Finding(r, "low", "b", "m", "f"))]
    assert safe == ["S3-VERSIONING", "S3-PUBLIC", "ACCT-NO-PW-POLICY"]


def test_versioning_fix_text():
    files = fixes.propose(Finding("S3-VERSIONING", "medium", "my-bucket", "m", "f"))
    (path, text), = files.items()
    assert path.endswith("my_bucket_versioning.tf")
    assert 'bucket = "my-bucket"' in text and 'status = "Enabled"' in text


# ---------- github pr ----------
def test_open_fix_pr_calls_in_order():
    calls = []
    def request(method, url, **kw):
        calls.append((method, url.replace("https://api.github.com/repos/o/r", "")))
        r = MagicMock()
        r.json.return_value = {"object": {"sha": "abc"}, "html_url": "https://github.com/o/r/pull/1"}
        return r
    http = MagicMock(); http.request = request
    url = github_pr.open_fix_pr("t", "o/r", "main", "fixes", {"terraform/fixes/a.tf": "x"}, "T", "B", http=http)
    assert url.endswith("/pull/1")
    assert [c[0] for c in calls] == ["GET", "POST", "PUT", "POST"]
    assert calls[1][1] == "/git/refs" and calls[3][1] == "/pulls"


# ---------- drift ----------
def _state(resources):
    return {"values": {"root_module": {"resources": resources}}}


def _vpc_sg(session, ports=(22,), cidr="10.0.0.0/8"):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName="web", Description="t", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": cidr}]} for p in ports])
    return gid


def _sg_resource(gid, ports=(22,), cidr="10.0.0.0/8"):
    return {"type": "aws_security_group", "values": {"id": gid, "ingress": [
        {"protocol": "tcp", "from_port": p, "to_port": p, "cidr_blocks": [cidr], "ipv6_cidr_blocks": []}
        for p in ports]}}


def test_no_drift_when_matching(session):
    gid = _vpc_sg(session)
    assert drift.check_drift(session, _state([_sg_resource(gid)])) == []


def test_sg_rule_added_by_hand_is_drift(session):
    gid = _vpc_sg(session)
    session.client("ec2").authorize_security_group_ingress(GroupId=gid, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    f = drift.check_drift(session, _state([_sg_resource(gid)]))
    assert [x.rule_id for x in f] == ["DRIFT"] and f[0].resource == gid


def test_deleted_volume_and_resized_volume(session):
    ec2 = session.client("ec2")
    v = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20)["VolumeId"]
    state = _state([
        {"type": "aws_ebs_volume", "values": {"id": v, "size": 8, "encrypted": False}},
        {"type": "aws_ebs_volume", "values": {"id": "vol-gone", "size": 8, "encrypted": False}}])
    msgs = [f.message for f in drift.check_drift(session, state)]
    assert any("Volume size" in m for m in msgs)
    assert any("deleted outside Terraform" in m for m in msgs)


def test_instance_type_change_is_drift(session):
    ec2 = session.client("ec2")
    iid = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t3.large")["Instances"][0]["InstanceId"]
    state = _state([{"type": "aws_instance", "values": {"id": iid, "instance_type": "t3.micro"}}])
    f = drift.check_drift(session, state)
    assert any("Instance type" in x.message for x in f)


def test_untracked_resources_found(session):
    session.client("s3").create_bucket(Bucket="made-by-hand")
    gid = _vpc_sg(session)
    f = drift.check_drift(session, _state([]))
    kinds = {(x.rule_id, x.resource) for x in f}
    assert ("DRIFT-UNTRACKED", "made-by-hand") in kinds
    assert ("DRIFT-UNTRACKED", gid) in kinds


def test_versioning_drift(session):
    c = session.client("s3")
    c.create_bucket(Bucket="data-bucket")
    state = _state([
        {"type": "aws_s3_bucket", "values": {"id": "data-bucket", "bucket": "data-bucket"}},
        {"type": "aws_s3_bucket_versioning", "values": {
            "bucket": "data-bucket", "versioning_configuration": [{"status": "Enabled"}]}}])
    f = drift.check_drift(session, state)
    assert any("Bucket versioning" in x.message for x in f)
    c.put_bucket_versioning(Bucket="data-bucket", VersioningConfiguration={"Status": "Enabled"})
    assert drift.check_drift(session, state) == []


def test_child_module_resources_are_read(session):
    gid = _vpc_sg(session)
    state = {"values": {"root_module": {"child_modules": [{"resources": [_sg_resource(gid)]}]}}}
    assert drift.check_drift(session, state) == []


# ---------- measure ----------
def test_measure_counts_caught_and_missed():
    from scanner.measure import measure
    planted = [{"rule_id": "A", "resource": "x"}, {"rule_id": "B", "resource": "y"}]
    findings = [{"rule_id": "A", "resource": "x"}, {"rule_id": "C", "resource": "z"}]
    caught, total, missed = measure(planted, findings)
    assert (caught, total, missed) == (1, 2, [("B", "y")])


def test_a_drift_run_does_not_resolve_security_findings():
    s = Store()
    sec = Finding("S3-PUBLIC", "high", "bucket", "m", "f")             # kind "security"
    s.record([sec], kinds={"security", "waste"})
    new, resolved = s.record([], kinds={"drift"})                      # a drift run that found nothing
    assert resolved == []
    new, _ = s.record([sec], kinds={"security", "waste"})              # next scan: not new again
    assert new == []


def test_a_scan_still_resolves_what_was_fixed():
    s = Store()
    sec = Finding("S3-PUBLIC", "high", "bucket", "m", "f")
    s.record([sec], kinds={"security", "waste"})
    _, resolved = s.record([], kinds={"security", "waste"})
    assert resolved == [("S3-PUBLIC", "bucket")]
