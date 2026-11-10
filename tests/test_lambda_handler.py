import boto3
import pytest
from moto import mock_aws

from scanner import lambda_handler as lh
from scanner.models import Finding

BUCKET = "drift-test"


class FakePost:
    def __init__(self):
        self.sent = []

    def __call__(self, url, json, timeout):
        self.sent.append(json["text"])
        return type("R", (), {"raise_for_status": lambda self: None})()


@pytest.fixture
def s3(monkeypatch, tmp_path):
    monkeypatch.setenv("DRIFT_BUCKET", BUCKET)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/x")
    monkeypatch.setattr(lh, "DB_PATH", str(tmp_path / "findings.db"))
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def finding(rule="S3-PUBLIC", resource="bucket-a"):
    return Finding(rule, "high", resource, "Bucket is open to the world.", "Block public access.")


def scan_returns(monkeypatch, findings, errors=()):
    monkeypatch.setattr(lh, "run_all", lambda session: (list(findings), list(errors)))


def test_first_run_alerts_on_new_findings_and_saves_the_table(s3, monkeypatch):
    scan_returns(monkeypatch, [finding()])
    post = FakePost()
    out = lh.handler({}, None, s3=s3, session=object(), post=post)
    assert out["new"] == 1 and out["started_from_existing_db"] is False
    assert len(post.sent) == 1 and "S3-PUBLIC" in post.sent[0]
    assert lh.DB_KEY in [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET)["Contents"]]


def test_second_run_does_not_repeat_an_alert(s3, monkeypatch):
    scan_returns(monkeypatch, [finding()])
    lh.handler({}, None, s3=s3, session=object(), post=FakePost())
    post = FakePost()
    out = lh.handler({}, None, s3=s3, session=object(), post=post)
    assert out["new"] == 0 and out["started_from_existing_db"] is True
    assert post.sent == []                      # the whole point of keeping the table in S3


def test_a_fixed_then_returning_finding_alerts_again(s3, monkeypatch):
    scan_returns(monkeypatch, [finding()])
    lh.handler({}, None, s3=s3, session=object(), post=FakePost())
    scan_returns(monkeypatch, [])
    out = lh.handler({}, None, s3=s3, session=object(), post=FakePost())
    assert out["resolved"] == 1
    scan_returns(monkeypatch, [finding()])
    post = FakePost()
    assert lh.handler({}, None, s3=s3, session=object(), post=post)["new"] == 1 and len(post.sent) == 1


def test_a_rule_that_cannot_run_is_alerted_and_fails_the_run(s3, monkeypatch):
    scan_returns(monkeypatch, [], errors=[{"rule": "public_bucket", "error": "ClientError: AccessDenied"}])
    post = FakePost()
    with pytest.raises(RuntimeError, match="1 rule"):
        lh.handler({}, None, s3=s3, session=object(), post=post)
    assert "blind" in post.sent[0] and "public_bucket" in post.sent[0]


def test_slack_being_down_does_not_hide_the_result(s3, monkeypatch):
    scan_returns(monkeypatch, [finding()])

    def broken(url, json, timeout):
        raise RuntimeError("Slack answered 500")
    out = lh.handler({}, None, s3=s3, session=object(), post=broken)
    assert out["new"] == 1


def test_scans_a_real_fake_account_end_to_end(s3, monkeypatch):
    """No stubbing: the real rules run against a moto account with one public bucket."""
    aws = boto3.Session(region_name="us-east-1")
    aws.client("s3").create_bucket(Bucket="planted-open-bucket")
    post = FakePost()
    out = lh.handler({}, None, s3=s3, session=aws, post=post)
    assert out["findings"] > 0 and out["rule_errors"] == 0
    assert post.sent and "planted-open-bucket" in post.sent[0]
