from datetime import datetime, timezone
from botocore.exceptions import ClientError
from scanner.models import Finding

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _has_star_statement(doc):
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        acts = s.get("Action", [])
        res = s.get("Resource", [])
        acts = [acts] if isinstance(acts, str) else acts
        res = [res] if isinstance(res, str) else res
        if s.get("Effect") == "Allow" and "*" in acts and "*" in res:
            return True
    return False


def admin_policy_on_user(session):
    """CIS 1.16: do not attach full admin policies directly to users."""
    iam = session.client("iam")
    out = []
    for u in iam.list_users()["Users"]:
        name = u["UserName"]
        bad = any(p["PolicyArn"] == ADMIN_ARN
                  for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"])
        if not bad:
            for pname in iam.list_user_policies(UserName=name)["PolicyNames"]:
                doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
                if _has_star_statement(doc):
                    bad = True
                    break
        if not bad:
            for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
                ver = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
                if _has_star_statement(doc):
                    bad = True
                    break
        if bad:
            out.append(Finding(
                "IAM-ADMIN-USER", "high", name,
                "User has a policy that allows every action on every resource.",
                "Detach it and grant only the permissions the user needs, through a group or role."))
    return out


def user_without_mfa(session):
    """CIS 1.10: users who can sign in to the console need MFA."""
    iam = session.client("iam")
    out = []
    for u in iam.list_users()["Users"]:
        name = u["UserName"]
        try:
            iam.get_login_profile(UserName=name)
        except ClientError:
            continue  # no console password, so MFA does not apply
        if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            out.append(Finding(
                "IAM-NO-MFA", "high", name,
                "User can sign in to the console but has no MFA device.",
                "Require the user to register an MFA device."))
    return out


def old_access_key(session, max_age_days=90, now=None):
    """CIS 1.14: rotate access keys at least every 90 days."""
    iam = session.client("iam")
    now = now or datetime.now(timezone.utc)
    out = []
    for u in iam.list_users()["Users"]:
        for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]:
            age = (now - k["CreateDate"]).days
            if k["Status"] == "Active" and age > max_age_days:
                out.append(Finding(
                    "IAM-OLD-KEY", "medium", f"{u['UserName']}/{k['AccessKeyId']}",
                    f"Access key is {age} days old.",
                    "Create a new key, switch your tools to it, then delete the old one."))
    return out
