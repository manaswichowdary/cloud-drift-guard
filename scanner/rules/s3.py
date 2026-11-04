from botocore.exceptions import ClientError
from scanner.models import Finding

PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _buckets(session):
    s3 = session.client("s3")
    return s3, [b["Name"] for b in s3.list_buckets().get("Buckets", [])]


def public_bucket(session):
    """CIS 2.1.4: a bucket should not be open to the world."""
    s3, names = _buckets(session)
    out = []
    for name in names:
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(cfg.get(k) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except ClientError:
            fully_blocked = False  # no block configured at all
        grants = s3.get_bucket_acl(Bucket=name)["Grants"]
        public_acl = any(g["Grantee"].get("URI") in PUBLIC_GROUPS for g in grants)
        # Only a problem if something actually opens it. A missing block alone is not enough.
        if public_acl and not fully_blocked:
            out.append(Finding(
                "S3-PUBLIC", "high", name,
                "Bucket ACL grants access to everyone and public access is not blocked.",
                "Turn on all four Block Public Access settings and remove the public ACL grant."))
    return out


def versioning_off(session):
    """CIS 2.1.3 style: versioning protects against accidental deletes."""
    s3, names = _buckets(session)
    out = []
    for name in names:
        if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
            out.append(Finding(
                "S3-VERSIONING", "medium", name,
                "Bucket versioning is not enabled.",
                "Enable versioning on the bucket."))
    return out


def access_logging_off(session):
    """CIS 3.6 style: log who touches the bucket."""
    s3, names = _buckets(session)
    out = []
    for name in names:
        if "LoggingEnabled" not in s3.get_bucket_logging(Bucket=name):
            out.append(Finding(
                "S3-LOGGING", "low", name,
                "Server access logging is not enabled.",
                "Send access logs to a separate logging bucket."))
    return out
