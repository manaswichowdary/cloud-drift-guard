"""The measurement from the project plan: how many planted mistakes does the scanner catch?

terraform/main.tf plants 12 mistakes. This test creates the same 12 with boto3 on an emulated account,
plus a set of correctly configured resources, then checks that every planted mistake is found and
nothing is flagged on the clean resources.
"""
import io
import json
import zipfile

from scanner.runner import run_all

# (rule id, resource) for each of the 12 planted mistakes. Names match terraform/main.tf.
PLANTED = [
    ("S3-PUBLIC", "drift-demo-public"),
    ("S3-VERSIONING", "drift-demo-public"),
    ("S3-LOGGING", "drift-demo-public"),
    ("SG-SSH-OPEN", "drift-demo-ssh-open"),
    ("SG-ALL-OPEN", "drift-demo-all-open"),
    ("EBS-UNENCRYPTED", "drift-demo-unencrypted-volume"),
    ("EBS-UNATTACHED", "drift-demo-unencrypted-volume"),
    ("EIP-UNUSED", "drift-demo-unused-eip"),
    ("IAM-ADMIN-USER", "drift-demo-admin"),
    ("IAM-NO-MFA", "drift-demo-admin"),
    ("LAMBDA-OLD-RUNTIME", "drift-demo-old-runtime"),
    ("SG-DEFAULT-RULES", "default"),
]


def _build(session):
    s3, ec2, iam, fn = (session.client(x) for x in ("s3", "ec2", "iam", "lambda"))
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    ids = {}

    # --- the 12 planted mistakes ---
    s3.create_bucket(Bucket="drift-demo-public")
    s3.put_bucket_acl(Bucket="drift-demo-public", ACL="public-read")

    ids["drift-demo-ssh-open"] = ec2.create_security_group(
        GroupName="drift-demo-ssh-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ids["drift-demo-ssh-open"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ids["drift-demo-all-open"] = ec2.create_security_group(
        GroupName="drift-demo-all-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ids["drift-demo-all-open"], IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    default = [g for g in ec2.describe_security_groups()["SecurityGroups"] if g["GroupName"] == "default"][0]
    ec2.authorize_security_group_ingress(GroupId=default["GroupId"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    ids["default"] = default["GroupId"]

    ids["drift-demo-unencrypted-volume"] = ec2.create_volume(
        AvailabilityZone="us-east-1a", Size=8, Encrypted=False)["VolumeId"]
    ids["drift-demo-unused-eip"] = ec2.allocate_address(Domain="vpc")["AllocationId"]

    iam.create_user(UserName="drift-demo-admin")
    iam.put_user_policy(UserName="drift-demo-admin", PolicyName="everything", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    iam.create_login_profile(UserName="drift-demo-admin", Password="Sup3r-Secret-Pass!", PasswordResetRequired=False)

    role = iam.create_role(RoleName="drift-demo-fn", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.py", "def h(e, c): return 1")
    fn.create_function(FunctionName="drift-demo-old-runtime", Runtime="python3.8", Role=role,
                       Handler="a.h", Code={"ZipFile": buf.getvalue()})
    fn.create_function(FunctionName="drift-demo-current", Runtime="python3.13", Role=role,
                       Handler="a.h", Code={"ZipFile": buf.getvalue()})

    # --- correctly configured resources that must NOT be flagged ---
    s3.create_bucket(Bucket="drift-demo-logs")
    s3.put_bucket_acl(Bucket="drift-demo-logs", GrantWrite='uri="http://acs.amazonaws.com/groups/s3/LogDelivery"',
                      GrantReadACP='uri="http://acs.amazonaws.com/groups/s3/LogDelivery"')
    s3.create_bucket(Bucket="drift-demo-good")
    s3.put_public_access_block(Bucket="drift-demo-good", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket="drift-demo-good", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_logging(Bucket="drift-demo-good", BucketLoggingStatus={"LoggingEnabled": {
        "TargetBucket": "drift-demo-logs", "TargetPrefix": "good/"}})
    ids["drift-demo-good-sg"] = ec2.create_security_group(
        GroupName="drift-demo-good-sg", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=ids["drift-demo-good-sg"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ids["good-volume"] = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)["VolumeId"]
    inst = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                             Placement={"AvailabilityZone": "us-east-1a"})["Instances"][0]["InstanceId"]
    ec2.attach_volume(VolumeId=ids["good-volume"], InstanceId=inst, Device="/dev/sdf")
    iam.create_user(UserName="drift-demo-service")
    return ids


def test_all_12_planted_mistakes_are_caught_with_no_false_alarms_on_clean_resources(session):
    ids = _build(session)
    findings, errors = run_all(session)
    assert errors == []
    got = {(f.rule_id, f.resource) for f in findings}

    resolve = lambda name: ids.get(name, name)  # noqa: E731
    missing = [(r, n) for r, n in PLANTED if (r, resolve(n)) not in got]
    assert missing == [], f"missed planted mistakes: {missing}"
    assert len(PLANTED) == 12

    clean = {"drift-demo-good", "drift-demo-logs", ids["drift-demo-good-sg"], ids["good-volume"],
             "drift-demo-service", "drift-demo-current"}
    # drift-demo-logs has no versioning or logging itself, so only the target bucket rules may touch it.
    false_alarms = [(r, res) for r, res in got if res in clean and res != "drift-demo-logs"]
    assert false_alarms == [], f"false alarms on clean resources: {false_alarms}"
