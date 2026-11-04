import json
from datetime import datetime, timedelta, timezone
from scanner.rules import iam, lambda_fn, account

STAR = json.dumps({"Version": "2012-10-17",
                   "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
READ = json.dumps({"Version": "2012-10-17",
                   "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})


def test_inline_star_policy_flagged(session):
    c = session.client("iam")
    c.create_user(UserName="alice")
    c.put_user_policy(UserName="alice", PolicyName="p", PolicyDocument=STAR)
    assert [f.resource for f in iam.admin_policy_on_user(session)] == ["alice"]


def test_attached_admin_managed_policy_flagged(session):
    c = session.client("iam")
    c.create_user(UserName="bob")
    arn = c.create_policy(PolicyName="everything", PolicyDocument=STAR)["Policy"]["Arn"]
    c.attach_user_policy(UserName="bob", PolicyArn=arn)
    assert [f.resource for f in iam.admin_policy_on_user(session)] == ["bob"]


def test_read_only_policy_not_flagged(session):
    c = session.client("iam")
    c.create_user(UserName="carol")
    c.put_user_policy(UserName="carol", PolicyName="p", PolicyDocument=READ)
    assert iam.admin_policy_on_user(session) == []


def test_console_user_without_mfa_flagged(session):
    c = session.client("iam")
    c.create_user(UserName="dave")
    c.create_login_profile(UserName="dave", Password="Sup3r-Secret-Pass!", PasswordResetRequired=False)
    c.create_user(UserName="svc")  # no console access, not flagged
    assert [f.resource for f in iam.user_without_mfa(session)] == ["dave"]


def test_old_access_key(session):
    c = session.client("iam")
    c.create_user(UserName="erin")
    key = c.create_access_key(UserName="erin")["AccessKey"]["AccessKeyId"]
    future = datetime.now(timezone.utc) + timedelta(days=120)
    assert [f.resource for f in iam.old_access_key(session, now=future)] == [f"erin/{key}"]
    assert iam.old_access_key(session) == []


def test_deprecated_lambda_runtime(session):
    c = session.client("iam")
    role = c.create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    fn = session.client("lambda")
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.py", "def h(e, c): return 1")
    for name, runtime in (("old", "python3.8"), ("new", "python3.13")):
        fn.create_function(FunctionName=name, Runtime=runtime, Role=role, Handler="a.h",
                           Code={"ZipFile": buf.getvalue()})
    assert [f.resource for f in lambda_fn.deprecated_runtime(session)] == ["old"]


def test_no_password_policy_then_set(session):
    assert [f.rule_id for f in account.no_password_policy(session)] == ["ACCT-NO-PW-POLICY"]
    session.client("iam").update_account_password_policy(MinimumPasswordLength=14)
    assert account.no_password_policy(session) == []


def test_no_cloudtrail_flagged(session):
    assert [f.rule_id for f in account.no_cloudtrail(session)] == ["ACCT-NO-CLOUDTRAIL"]


def test_root_access_key_clean_by_default(session):
    assert account.root_access_key(session) == []
