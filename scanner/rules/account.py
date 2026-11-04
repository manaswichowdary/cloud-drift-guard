from botocore.exceptions import ClientError
from scanner.models import Finding


def no_password_policy(session):
    """CIS 1.8: set a password policy for IAM users."""
    iam = session.client("iam")
    try:
        iam.get_account_password_policy()
        return []
    except ClientError:
        return [Finding(
            "ACCT-NO-PW-POLICY", "medium", "account",
            "No IAM password policy is set.",
            "Set a minimum length of 14 and require a mix of character types.")]


def root_access_key(session):
    """CIS 1.4: the root user should have no access keys."""
    iam = session.client("iam")
    if iam.get_account_summary()["SummaryMap"].get("AccountAccessKeysPresent", 0) > 0:
        return [Finding(
            "ACCT-ROOT-KEY", "high", "root",
            "The root user has an access key.",
            "Delete the root access key and use an IAM role or user instead.")]
    return []


def no_cloudtrail(session):
    """CIS 3.1: keep an audit log of API calls in every account."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    if not trails:
        return [Finding(
            "ACCT-NO-CLOUDTRAIL", "high", "account",
            "No CloudTrail trail exists.",
            "Create a multi region trail that writes to a locked down bucket.")]
    return []
