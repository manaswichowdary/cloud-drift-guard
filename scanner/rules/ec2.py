from datetime import datetime, timedelta, timezone
from scanner.models import Finding

WORLD = ("0.0.0.0/0", "::/0")
# Rough us-east-1 list prices, used only for the waste estimate.
GP3_USD_PER_GB_MONTH = 0.08
EIP_USD_PER_MONTH = 3.65  # $0.005 per hour for an idle public IPv4 address


def _sgs(session):
    ec2 = session.client("ec2")
    return ec2.describe_security_groups()["SecurityGroups"]


def _open_to_world(perm):
    v4 = any(r.get("CidrIp") in WORLD for r in perm.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") in WORLD for r in perm.get("Ipv6Ranges", []))
    return v4 or v6


def _covers_port(perm, port):
    if perm.get("IpProtocol") == "-1":
        return True
    return perm.get("FromPort", 0) <= port <= perm.get("ToPort", 0)


def ssh_open_to_world(session):
    """CIS 5.2: no security group should allow SSH from anywhere."""
    out = []
    for sg in _sgs(session):
        for perm in sg["IpPermissions"]:
            if _open_to_world(perm) and _covers_port(perm, 22) and perm.get("IpProtocol") != "-1":
                out.append(Finding(
                    "SG-SSH-OPEN", "high", sg["GroupId"],
                    f"Security group {sg['GroupName']} allows SSH (22) from the whole internet.",
                    "Limit the SSH rule to your own IP range or use Session Manager instead."))
                break
    return out


def all_ports_open(session):
    """A rule that opens every port to the world."""
    out = []
    for sg in _sgs(session):
        for perm in sg["IpPermissions"]:
            if _open_to_world(perm) and perm.get("IpProtocol") == "-1":
                out.append(Finding(
                    "SG-ALL-OPEN", "high", sg["GroupId"],
                    f"Security group {sg['GroupName']} allows all traffic from the whole internet.",
                    "Replace it with rules for only the ports the service needs."))
                break
    return out


def default_sg_has_rules(session):
    """CIS 5.4: the default security group should allow nothing."""
    out = []
    for sg in _sgs(session):
        if sg["GroupName"] == "default" and (sg["IpPermissions"] or sg["IpPermissionsEgress"]):
            # Egress to anywhere is the AWS default, so only flag inbound rules.
            if sg["IpPermissions"]:
                out.append(Finding(
                    "SG-DEFAULT-RULES", "medium", sg["GroupId"],
                    "The default security group has inbound rules.",
                    "Remove all rules from the default group and use named groups instead."))
    return out


def unencrypted_volume(session):
    """CIS 2.2.1: EBS volumes should be encrypted."""
    ec2 = session.client("ec2")
    out = []
    for v in ec2.describe_volumes()["Volumes"]:
        if not v.get("Encrypted"):
            out.append(Finding(
                "EBS-UNENCRYPTED", "medium", v["VolumeId"],
                "EBS volume is not encrypted.",
                "Create an encrypted copy from a snapshot and swap it in."))
    return out


def unattached_volume(session):
    """Waste: a volume nobody uses still bills every month."""
    ec2 = session.client("ec2")
    out = []
    for v in ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])["Volumes"]:
        out.append(Finding(
            "EBS-UNATTACHED", "low", v["VolumeId"],
            f"{v['Size']} GiB volume is not attached to any instance.",
            "Snapshot it if you need the data, then delete the volume.",
            kind="waste", monthly_usd=round(v["Size"] * GP3_USD_PER_GB_MONTH, 2)))
    return out


def unassociated_eip(session):
    """Waste: AWS charges for public IPs that are not in use."""
    ec2 = session.client("ec2")
    out = []
    for a in ec2.describe_addresses()["Addresses"]:
        if "AssociationId" not in a:
            out.append(Finding(
                "EIP-UNUSED", "low", a.get("AllocationId", a.get("PublicIp", "unknown")),
                "Elastic IP is not associated with anything.",
                "Release the address.",
                kind="waste", monthly_usd=EIP_USD_PER_MONTH))
    return out


def idle_instance(session, days=7, cpu_threshold=5.0, now=None):
    """Waste: a running server that has barely used its CPU for a week."""
    ec2 = session.client("ec2")
    cw = session.client("cloudwatch")
    now = now or datetime.now(timezone.utc)
    out = []
    reservations = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}])["Reservations"]
    for r in reservations:
        for inst in r["Instances"]:
            iid = inst["InstanceId"]
            stats = cw.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                StartTime=now - timedelta(days=days), EndTime=now,
                Period=3600 * 6, Statistics=["Average"])["Datapoints"]
            if not stats:
                continue  # no data means we cannot say it is idle
            avg = sum(p["Average"] for p in stats) / len(stats)
            if avg < cpu_threshold:
                out.append(Finding(
                    "EC2-IDLE", "low", iid,
                    f"Average CPU was {avg:.1f}% over {days} days.",
                    "Stop or terminate the instance, or move to a smaller size.",
                    kind="waste"))
    return out
