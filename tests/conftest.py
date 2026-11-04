import os
import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    # Never let a test reach a real account.
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")
