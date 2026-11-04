"""Every rule is a small function: it takes a boto3 session and returns a list of Findings."""
from . import s3, ec2, iam, lambda_fn, account

ALL_RULES = (
    s3.public_bucket,
    s3.versioning_off,
    s3.access_logging_off,
    ec2.ssh_open_to_world,
    ec2.all_ports_open,
    ec2.default_sg_has_rules,
    ec2.unencrypted_volume,
    ec2.unattached_volume,
    ec2.unassociated_eip,
    ec2.idle_instance,
    iam.admin_policy_on_user,
    iam.user_without_mfa,
    iam.old_access_key,
    lambda_fn.deprecated_runtime,
    account.no_password_policy,
    account.root_access_key,
    account.no_cloudtrail,
)
