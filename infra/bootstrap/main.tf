# ---------------------------------------------------------------------------
# One-time bootstrap: everything the app stack and its pipelines depend on but must never
# destroy - the S3 bucket for Terraform state, the account's GitHub OIDC provider, and the
# GitHub Actions roles that run Terraform (ci_roles.tf).
# Run once:
#   cd infra/bootstrap
#   copy bootstrap.tfvars.example bootstrap.tfvars   (then edit it)
#   terraform init && terraform apply -var-file=bootstrap.tfvars
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"

  validation {
    condition     = contains(jsondecode(file("${path.module}/../../policy/rules.json")).allowed_regions, var.region)
    error_message = "This region is not allowed by policy/rules.json (allowed_regions)."
  }
}

variable "project_name" {
  type    = string
  default = "aws-pipeline-2"
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = var.project_name, ManagedBy = "terraform", Purpose = "terraform-state" }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "state" {
  # checkov:skip=CKV_AWS_18:Access logging would need another bucket; state access is already audited by CloudTrail
  # checkov:skip=CKV_AWS_144:Cross-region replication is unnecessary for a single-region lab
  # checkov:skip=CKV2_AWS_62:No consumers need event notifications for state files
  bucket = "${var.project_name}-tfstate-${data.aws_caller_identity.current.account_id}"

  lifecycle {
    prevent_destroy = true # state history is precious - delete manually if you ever need to
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled" # every state change is kept - you can roll back a bad apply
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms" # AWS-managed key; state contains resource details and must be encrypted
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.state.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

output "state_bucket" {
  description = "Put this in backend-prod.hcl / backend-dev.hcl as `bucket`."
  value       = aws_s3_bucket.state.bucket
}
