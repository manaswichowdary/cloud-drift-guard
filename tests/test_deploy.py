import zipfile

import boto3
import pytest
from moto import mock_aws

from deploy import deploy_aws as d

REGION = "us-east-1"
BUCKET = "drift-guard-data-test"


def tiny_zip(tmp_path):
    path = tmp_path / "f.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("scanner/__init__.py", "")
        z.writestr("scanner/lambda_handler.py", "def handler(event, context):\n    return {}\n")
    return str(path)


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def test_deploy_creates_everything(aws, tmp_path):
    info = d.deploy(aws, REGION, BUCKET, tiny_zip(tmp_path), "https://hooks.example/x")
    s3, lam, events = aws.client("s3"), aws.client("lambda"), aws.client("events")
    assert all(s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"].values())
    assert s3.get_bucket_versioning(Bucket=BUCKET)["Status"] == "Enabled"
    cfg = lam.get_function_configuration(FunctionName=d.FUNCTION)
    assert cfg["Handler"] == "scanner.lambda_handler.handler" and cfg["Timeout"] == 300
    assert cfg["Environment"]["Variables"] == {"DRIFT_BUCKET": BUCKET, "SLACK_WEBHOOK_URL": "https://hooks.example/x"}
    rule = events.describe_rule(Name=d.RULE)
    assert rule["ScheduleExpression"] == "rate(5 minutes)" and rule["State"] == "ENABLED"
    assert events.list_targets_by_rule(Rule=d.RULE)["Targets"][0]["Arn"] == info["function"]


def test_the_role_is_read_only_for_the_account(aws, tmp_path):
    d.deploy(aws, REGION, BUCKET, tiny_zip(tmp_path))
    policy = aws.client("iam").get_role_policy(RoleName=d.ROLE, PolicyName="drift-guard-scan-access")["PolicyDocument"]
    for statement in policy["Statement"]:
        for action in statement["Action"]:
            assert action != "*" and not action.endswith(":*")
    scanner = policy["Statement"][0]
    assert scanner["Resource"] == "*"
    for action in scanner["Action"]:                    # account wide statement may only read settings
        assert action.split(":")[1].startswith(("Describe", "Get", "List"))
        assert action not in ("s3:GetObject",)
    for statement in policy["Statement"][1:3]:          # object access is limited to the findings bucket
        assert BUCKET in statement["Resource"]


def test_every_action_the_rules_call_is_allowed():
    """If a rule starts using a new AWS call, this fails until the role is updated, instead of failing in production."""
    import re
    import pathlib
    # Two boto3 method names differ from the IAM permission that guards them.
    aliases = {"listbuckets": "listallmybuckets", "getpublicaccessblock": "getbucketpublicaccessblock"}
    wanted = set()
    for path in pathlib.Path(d.ROOT, "scanner", "rules").glob("*.py"):
        text = path.read_text()
        calls = re.findall(r"\.((?:describe|list|get)_[a-z_]+)\(", text)
        for c in set(calls):
            wanted.add(aliases.get(c.replace("_", ""), c.replace("_", "")))
    allowed = {a.split(":")[1].lower() for a in d.SCANNER_READ_ACTIONS}
    missing = {w for w in wanted if w not in allowed and w not in {"getpaginator"}}
    assert not missing, missing


def test_running_the_deploy_twice_is_safe(aws, tmp_path):
    z = tiny_zip(tmp_path)
    d.deploy(aws, REGION, BUCKET, z)
    d.deploy(aws, REGION, BUCKET, z, "https://hooks.example/y", "rate(15 minutes)")
    cfg = aws.client("lambda").get_function_configuration(FunctionName=d.FUNCTION)
    assert cfg["Environment"]["Variables"]["SLACK_WEBHOOK_URL"] == "https://hooks.example/y"
    assert aws.client("events").describe_rule(Name=d.RULE)["ScheduleExpression"] == "rate(15 minutes)"
    assert len(aws.client("events").list_targets_by_rule(Rule=d.RULE)["Targets"]) == 1
