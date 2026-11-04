# The 12 planted mistakes, as the scanner should report them. `make measure` compares this with a scan.
output "planted" {
  value = concat(
    [
      { rule_id = "S3-PUBLIC", resource = aws_s3_bucket.public.id },
      { rule_id = "S3-VERSIONING", resource = aws_s3_bucket.public.id },
      { rule_id = "S3-LOGGING", resource = aws_s3_bucket.public.id },
      { rule_id = "SG-SSH-OPEN", resource = aws_security_group.ssh_open.id },
      { rule_id = "SG-ALL-OPEN", resource = aws_security_group.all_open.id },
      { rule_id = "SG-DEFAULT-RULES", resource = aws_default_security_group.default.id },
      { rule_id = "EBS-UNENCRYPTED", resource = aws_ebs_volume.unencrypted.id },
      { rule_id = "EBS-UNATTACHED", resource = aws_ebs_volume.unencrypted.id },
      { rule_id = "EIP-UNUSED", resource = aws_eip.unused.allocation_id },
      { rule_id = "IAM-ADMIN-USER", resource = aws_iam_user.admin.name },
      { rule_id = "IAM-NO-MFA", resource = aws_iam_user.admin.name },
    ],
    var.plant_old_lambda ? [{ rule_id = "LAMBDA-OLD-RUNTIME", resource = "drift-demo-old-runtime" }] : []
  )
}
