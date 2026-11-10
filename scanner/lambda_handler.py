"""The scheduled scan on AWS Lambda.

Lambda starts empty every time, so the SQLite findings table lives in S3: download it, scan the account the function
runs in, save the findings, alert Slack only about NEW findings, upload the table again.

Settings come from environment variables (set by the deploy script):
  DRIFT_BUCKET        the S3 bucket that holds the findings table
  SLACK_WEBHOOK_URL   optional, where alerts are posted

What it does not do: the Cost Explorer check (each call costs about a cent, so on a 5 minute schedule it would cost
real money) and Terraform drift (needs a Terraform state file). Both stay available from the command line.
"""
import os

import boto3
from botocore.exceptions import ClientError

from scanner import alerts, cost
from scanner.runner import run_all
from scanner.store import Store

DB_KEY = "db/findings.db"
DB_PATH = "/tmp/findings.db"
KINDS = {"security", "waste"}


def download_db(s3, bucket, path):
    """Fetch the findings table from the last run. Returns False on the very first run."""
    if os.path.exists(path):
        os.remove(path)     # a warm Lambda can reuse /tmp, so never trust what is already there
    try:
        s3.download_file(bucket, DB_KEY, path)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def build_message(new, errors):
    """One Slack message: new findings (capped by format_slack) plus any rule that could not run."""
    parts = []
    payload = alerts.format_slack(new, cost.monthly_waste(new))
    if payload:
        parts.append(payload["text"])
    if errors:
        parts.append("*Scanner problem:* " + str(len(errors)) + " rule(s) could not run, so those checks are blind:\n"
                     + "\n".join(f"• {e['rule']}: {e['error'][:120]}" for e in errors[:5]))
    return "\n\n".join(parts)


def handler(event, context, s3=None, session=None, post=None):
    bucket = os.environ["DRIFT_BUCKET"]
    s3 = s3 or boto3.client("s3")
    had_db = download_db(s3, bucket, DB_PATH)

    findings, errors = run_all(session or boto3.Session())
    store = Store(DB_PATH)
    try:
        new, resolved = store.record(findings, kinds=KINDS)
    finally:
        store.db.close()
    s3.upload_file(DB_PATH, bucket, DB_KEY)

    summary = {"findings": len(findings), "new": len(new), "resolved": len(resolved),
               "rule_errors": len(errors), "started_from_existing_db": had_db}
    print(summary)

    message = build_message(new, errors)
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if message and webhook:
        try:
            alerts.send_slack(webhook, {"text": message}, **({"post": post} if post else {}))
        except Exception as e:      # Slack being down must not hide the scan result
            print(f"could not send to Slack: {e}")
    if errors:
        raise RuntimeError(f"{len(errors)} rule(s) failed: " + "; ".join(e["rule"] for e in errors))
    return summary
