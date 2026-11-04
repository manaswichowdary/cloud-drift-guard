from datetime import datetime, timedelta, timezone
from scanner.rules import ec2 as rules


def _sg(session, name, perms):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description="t", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def test_ssh_open_flagged(session):
    gid = _sg(session, "ssh", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert [f.resource for f in rules.ssh_open_to_world(session)] == [gid]


def test_ssh_limited_not_flagged(session):
    _sg(session, "ssh", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                          "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    assert rules.ssh_open_to_world(session) == []


def test_wide_range_covering_22_flagged(session):
    gid = _sg(session, "wide", [{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535,
                                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert [f.resource for f in rules.ssh_open_to_world(session)] == [gid]


def test_all_ports_open(session):
    gid = _sg(session, "all", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert [f.resource for f in rules.all_ports_open(session)] == [gid]
    # the all traffic rule is reported by its own rule, not as an SSH finding
    assert rules.ssh_open_to_world(session) == []


def test_unencrypted_and_unattached_volume(session):
    ec2 = session.client("ec2")
    v = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)["VolumeId"]
    assert [f.resource for f in rules.unencrypted_volume(session)] == [v]
    assert [f.resource for f in rules.unattached_volume(session)] == [v]


def test_encrypted_volume_ok(session):
    session.client("ec2").create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)
    assert rules.unencrypted_volume(session) == []


def test_unassociated_eip(session):
    alloc = session.client("ec2").allocate_address(Domain="vpc")["AllocationId"]
    assert [f.resource for f in rules.unassociated_eip(session)] == [alloc]


def test_default_sg_with_inbound_rule_flagged(session):
    ec2 = session.client("ec2")
    default = [g for g in ec2.describe_security_groups()["SecurityGroups"] if g["GroupName"] == "default"][0]
    ec2.authorize_security_group_ingress(GroupId=default["GroupId"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert [f.rule_id for f in rules.default_sg_has_rules(session)] == ["SG-DEFAULT-RULES"]


def test_idle_instance_flagged_with_low_cpu(session, monkeypatch):
    ec2 = session.client("ec2")
    iid = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                            InstanceType="t3.micro")["Instances"][0]["InstanceId"]
    now = datetime.now(timezone.utc)
    cw = session.client("cloudwatch")
    cw.put_metric_data(Namespace="AWS/EC2", MetricData=[{
        "MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": iid}],
        "Timestamp": now - timedelta(days=1), "Value": 1.0, "Unit": "Percent"}])
    assert [f.resource for f in rules.idle_instance(session, now=now)] == [iid]


def test_busy_instance_not_flagged(session):
    ec2 = session.client("ec2")
    iid = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                            InstanceType="t3.micro")["Instances"][0]["InstanceId"]
    now = datetime.now(timezone.utc)
    session.client("cloudwatch").put_metric_data(Namespace="AWS/EC2", MetricData=[{
        "MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": iid}],
        "Timestamp": now - timedelta(days=1), "Value": 70.0, "Unit": "Percent"}])
    assert rules.idle_instance(session, now=now) == []


def test_instance_without_metrics_not_flagged(session):
    session.client("ec2").run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)
    assert rules.idle_instance(session) == []
