data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# ---------------------------------------------------------------------------
# AWS Config guardrails: continuously check the live environment (not just the code)
# and email when something drifts out of compliance.
# AWS allows ONE configuration recorder per region - set enable_aws_config = false
# if your account already has one (e.g. from AWS Control Tower).
# ---------------------------------------------------------------------------

locals {
  config_enabled = var.enable_aws_config ? 1 : 0

  config_rules = {
    "ecr-image-scanning-enabled"     = "ECR_PRIVATE_IMAGE_SCANNING_ENABLED"
    "ecr-tag-immutability-enabled"   = "ECR_PRIVATE_TAG_IMMUTABILITY_ENABLED"
    "ecs-containers-readonly-root"   = "ECS_CONTAINERS_READONLY_ACCESS"
    "ecs-containers-nonprivileged"   = "ECS_CONTAINERS_NONPRIVILEGED"
    "log-groups-encrypted"           = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
    "vpc-flow-logs-enabled"          = "VPC_FLOW_LOGS_ENABLED"
    "default-security-group-closed"  = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    "no-open-ssh"                    = "INCOMING_SSH_DISABLED"
    "root-account-mfa-enabled"       = "ROOT_ACCOUNT_MFA_ENABLED"
    "root-account-has-no-access-key" = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
}

# --- Delivery bucket for configuration snapshots ---
resource "aws_s3_bucket" "config" {
  # checkov:skip=CKV_AWS_18:Access logging would need a second bucket; this bucket only receives AWS Config snapshots
  # checkov:skip=CKV_AWS_144:Cross-region replication is unnecessary for lab configuration history
  # checkov:skip=CKV2_AWS_62:No consumers need S3 event notifications for Config snapshots
  # checkov:skip=CKV_AWS_145:SSE-S3 is used so the AWS Config service can write without extra KMS grants
  # checkov:skip=CKV_AWS_21:Versioning is enabled in aws_s3_bucket_versioning.config (scanner does not resolve count-indexed links)
  # checkov:skip=CKV2_AWS_6:Public access block is in aws_s3_bucket_public_access_block.config (scanner does not resolve count-indexed links)
  # checkov:skip=CKV2_AWS_61:Lifecycle rules are in aws_s3_bucket_lifecycle_configuration.config (scanner does not resolve count-indexed links)
  count         = local.config_enabled
  bucket        = "${var.name}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "config" {
  count                   = local.config_enabled
  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "config" {
  count  = local.config_enabled
  bucket = aws_s3_bucket.config[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = local.config_enabled
  bucket = aws_s3_bucket.config[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  count  = local.config_enabled
  bucket = aws_s3_bucket.config[0].id
  rule {
    id     = "expire-old-snapshots"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "config_bucket" {
  count = local.config_enabled
  statement {
    sid       = "ConfigAclCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config[0].arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid       = "ConfigWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config[0].arn, "${aws_s3_bucket.config[0].arn}/*"]
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

resource "aws_s3_bucket_policy" "config" {
  count  = local.config_enabled
  bucket = aws_s3_bucket.config[0].id
  policy = data.aws_iam_policy_document.config_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.config]
}

# --- Recorder ---
data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = local.config_enabled
  name               = "${var.name}-aws-config"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = local.config_enabled
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  # checkov:skip=CKV2_AWS_48:Records only the resource types the guardrail rules evaluate, to keep AWS Config costs near zero
  count    = local.config_enabled
  name     = "${var.name}-recorder"
  role_arn = aws_iam_role.config[0].arn

  # Record only the resource types our rules evaluate - keeps Config costs to pennies.
  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types = [
      "AWS::ECR::Repository",
      "AWS::ECS::TaskDefinition",
      "AWS::ECS::Service",
      "AWS::Logs::LogGroup",
      "AWS::EC2::VPC",
      "AWS::EC2::SecurityGroup",
    ]
    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }
}

resource "aws_config_delivery_channel" "main" {
  count          = local.config_enabled
  name           = "${var.name}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].bucket

  depends_on = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.config]
}

resource "aws_config_configuration_recorder_status" "main" {
  # checkov:skip=CKV2_AWS_45:Recorder is enabled; it intentionally records a scoped set of resource types (cost)
  count      = local.config_enabled
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "guardrails" {
  for_each = var.enable_aws_config ? local.config_rules : {}
  name     = "${var.name}-${each.key}"

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# --- Email when any guardrail finds a NON_COMPLIANT resource ---
resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  count       = local.config_enabled
  name        = "${var.name}-config-noncompliant"
  description = "AWS Config guardrail found a non-compliant resource"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName      = [for k, _ in local.config_rules : "${var.name}-${k}"]
      newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_noncompliant" {
  count = local.config_enabled
  rule  = aws_cloudwatch_event_rule.config_noncompliant[0].name
  arn   = var.alert_topic_arn

  input_transformer {
    input_paths = {
      rule     = "$.detail.configRuleName"
      resource = "$.detail.resourceId"
      type     = "$.detail.resourceType"
      time     = "$.time"
    }
    input_template = "\"[GUARDRAIL] <rule> is NON_COMPLIANT for <type> <resource> at <time>. Review it in AWS Config > Rules.\""
  }
}

# --- Optional: GuardDuty threat detection with ECS Fargate runtime monitoring ---
# 30-day free trial for new accounts, then billed. Enable with enable_guardduty = true.
resource "aws_guardduty_detector" "main" {
  # checkov:skip=CKV2_AWS_3:Single standalone account (no AWS Organization); enabled per region via this variable
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# --- Cost guardrail: email when forecast spend passes the budget ---
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
