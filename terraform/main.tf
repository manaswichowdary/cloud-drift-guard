# A small AWS environment with 12 planted mistakes, so the scanner has something to find.
# Do not copy this into a real project. It is wrong on purpose.

provider "aws" {
  region = var.region

  # These settings are only for the fake AWS (moto server). On real AWS they stay off and normal credentials are used.
  access_key                  = var.use_emulator ? "test" : null
  secret_key                  = var.use_emulator ? "test" : null
  skip_credentials_validation = var.use_emulator
  skip_metadata_api_check     = var.use_emulator
  skip_requesting_account_id  = var.use_emulator
  s3_use_path_style           = var.use_emulator

  dynamic "endpoints" {
    for_each = var.use_emulator ? [1] : []
    content {
      s3     = "http://localhost:4566"
      ec2    = "http://localhost:4566"
      iam    = "http://localhost:4566"
      lambda = "http://localhost:4566"
      sts    = "http://localhost:4566"
    }
  }
}

data "aws_vpc" "default" {
  default = true
}

# ---------------------------------------------------------------- planted mistakes 1 to 3
# A bucket that is open to the world (1), has no versioning (2) and no access logging (3).
resource "aws_s3_bucket" "public" {
  bucket = "drift-demo-public${var.name_suffix}"
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public" {
  bucket = aws_s3_bucket.public.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "public" {
  bucket     = aws_s3_bucket.public.id
  acl        = "public-read"
  depends_on = [aws_s3_bucket_ownership_controls.public, aws_s3_bucket_public_access_block.public]
}

# ---------------------------------------------------------------- planted mistakes 4, 5 and 12
# SSH open to the internet (4), every port open (5) and inbound rules on the default group (12).
resource "aws_security_group" "ssh_open" {
  name        = "drift-demo-ssh-open"
  description = "Planted: SSH from anywhere"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "all_open" {
  name        = "drift-demo-all-open"
  description = "Planted: all traffic from anywhere"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = data.aws_vpc.default.id

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# ---------------------------------------------------------------- planted mistakes 6 and 7
# A volume that is not encrypted (6) and is not attached to anything (7).
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "${var.region}a"
  size              = 1
  encrypted         = false
  tags              = { Name = "drift-demo-unencrypted-volume" }
}

# ---------------------------------------------------------------- planted mistake 8
resource "aws_eip" "unused" {
  domain = "vpc"
  tags   = { Name = "drift-demo-unused-eip" }
}

# ---------------------------------------------------------------- planted mistakes 9 and 10
# A user with full admin rights (9) who can sign in to the console without MFA (10).
resource "aws_iam_user" "admin" {
  name = "drift-demo-admin"
}

resource "aws_iam_user_policy" "admin_everything" {
  name = "everything"
  user = aws_iam_user.admin.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_user_login_profile" "admin" {
  user                    = aws_iam_user.admin.name
  password_reset_required = true
}

# ---------------------------------------------------------------- planted mistake 11
# A function on a runtime AWS no longer supports.
data "archive_file" "fn" {
  type        = "zip"
  output_path = "${path.module}/fn.zip"
  source {
    filename = "handler.py"
    content  = "def handler(event, context):\n    return 'ok'\n"
  }
}

resource "aws_iam_role" "fn" {
  name = "drift-demo-fn"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "old_runtime" {
  count            = var.plant_old_lambda ? 1 : 0
  function_name    = "drift-demo-old-runtime"
  role             = aws_iam_role.fn.arn
  handler          = "handler.handler"
  runtime          = "python3.8"
  filename         = data.archive_file.fn.output_path
  source_code_hash = data.archive_file.fn.output_base64sha256
}

resource "aws_lambda_function" "current" {
  function_name    = "drift-demo-current"
  role             = aws_iam_role.fn.arn
  handler          = "handler.handler"
  runtime          = "python3.13"
  filename         = data.archive_file.fn.output_path
  source_code_hash = data.archive_file.fn.output_base64sha256
}

# ---------------------------------------------------------------- done right, must NOT be flagged
resource "aws_s3_bucket" "logs" {
  bucket = "drift-demo-logs${var.name_suffix}"
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  bucket     = aws_s3_bucket.logs.id
  acl        = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.logs]
}

resource "aws_s3_bucket" "good" {
  bucket = "drift-demo-good${var.name_suffix}"
}

resource "aws_s3_bucket_public_access_block" "good" {
  bucket                  = aws_s3_bucket.good.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "good" {
  bucket = aws_s3_bucket.good.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "good" {
  bucket        = aws_s3_bucket.good.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "good/"
  depends_on    = [aws_s3_bucket_acl.logs]
}

resource "aws_security_group" "good" {
  name        = "drift-demo-good-sg"
  description = "HTTPS only"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Optional: one small server, so the idle server check has something real to look at.
data "aws_ssm_parameter" "al2023" {
  count = var.create_instance ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "demo" {
  count         = var.create_instance ? 1 : 0
  ami           = data.aws_ssm_parameter.al2023[0].value
  instance_type = "t3.micro"
  root_block_device {
    encrypted = true
  }
  tags = { Name = "drift-demo-instance" }
}

# Safety: a monthly budget that emails you, so a mistake here cannot quietly cost money.
resource "aws_budgets_budget" "monthly" {
  count        = var.alert_email == "" ? 0 : 1
  name         = "drift-demo-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
