"""Fix proposals for the rules that are safe to change automatically.

Only three rules qualify. Each fix only ADDS protection and cannot lock anyone out or delete data.
Everything else (open SSH rules, unused volumes, old keys) stays alert only, because a wrong fix there
can cut off access or destroy data.
"""

SAFE_RULES = ("S3-VERSIONING", "S3-PUBLIC", "ACCT-NO-PW-POLICY")


def _safe(name):
    return "".join(c if c.isalnum() else "_" for c in name)


def propose(finding):
    """Return {path: terraform text} for a safe finding, or None if the rule is alert only."""
    rid = finding.rule_id
    if rid == "S3-VERSIONING":
        n = _safe(finding.resource)
        return {f"terraform/fixes/{n}_versioning.tf": (
            f'resource "aws_s3_bucket_versioning" "fix_{n}" {{\n'
            f'  bucket = "{finding.resource}"\n'
            f'  versioning_configuration {{\n    status = "Enabled"\n  }}\n}}\n')}
    if rid == "S3-PUBLIC":
        n = _safe(finding.resource)
        return {f"terraform/fixes/{n}_block_public.tf": (
            f'resource "aws_s3_bucket_public_access_block" "fix_{n}" {{\n'
            f'  bucket                  = "{finding.resource}"\n'
            f'  block_public_acls       = true\n  ignore_public_acls      = true\n'
            f'  block_public_policy     = true\n  restrict_public_buckets = true\n}}\n')}
    if rid == "ACCT-NO-PW-POLICY":
        return {"terraform/fixes/password_policy.tf": (
            'resource "aws_iam_account_password_policy" "fix" {\n'
            '  minimum_password_length      = 14\n  require_lowercase_characters = true\n'
            '  require_uppercase_characters = true\n  require_numbers              = true\n'
            '  require_symbols              = true\n  password_reuse_prevention    = 5\n}\n')}
    return None
