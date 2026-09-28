# Automated incident response (SOAR-lite)
#   Alarm -> EventBridge -> Lambda: Logs Insights evidence -> NACL deny -> DynamoDB record -> SNS summary
#   Schedule -> Lambda: expire blocks after var.block_minutes

data "aws_caller_identity" "current" {}

resource "aws_dynamodb_table" "blocklist" {
  name         = "${var.name}-blocklist"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip"

  attribute {
    name = "ip"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

data "archive_file" "handler" {
  type        = "zip"
  source_file = var.source_file
  output_path = "${var.build_dir}/${var.name}-auto-response.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  # checkov:skip=CKV_AWS_338:Retention kept short to minimise cost in a lab environment
  name              = "/aws/lambda/${var.name}-auto-response"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "responder" {
  name               = "${var.name}-auto-response"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "responder" {
  # checkov:skip=CKV_AWS_356:logs:GetQueryResults works on a query ID and has no resource-level permissions; scoping it would deny the call
  statement {
    sid       = "QueryAppLogsForEvidence"
    actions   = ["logs:StartQuery"]
    resources = ["${var.app_log_group_arn}:*", var.app_log_group_arn]
  }
  statement {
    sid       = "ReadQueryResults"
    actions   = ["logs:GetQueryResults"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }
  statement {
    sid       = "DescribeNacl"
    actions   = ["ec2:DescribeNetworkAcls"]
    resources = ["*"] # EC2 Describe* has no resource-level support
  }
  statement {
    sid       = "ManageDenyRulesOnThisNaclOnly"
    actions   = ["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry"]
    resources = [var.nacl_arn]
  }
  statement {
    sid       = "Blocklist"
    actions   = ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Scan"]
    resources = [aws_dynamodb_table.blocklist.arn]
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [var.alert_topic_arn]
  }
  statement {
    sid       = "UseProjectKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"] # no resource-level support
  }
}

resource "aws_iam_role_policy" "responder" {
  name   = "least-privilege-response"
  role   = aws_iam_role.responder.id
  policy = data.aws_iam_policy_document.responder.json
}

resource "aws_lambda_function" "responder" {
  # checkov:skip=CKV_AWS_115:New AWS accounts have a concurrency limit of 10, so reserving concurrency can fail
  # checkov:skip=CKV_AWS_116:Async EventBridge invocations retry automatically; failures surface in logs and Lambda error metrics
  # checkov:skip=CKV_AWS_117:Running in a VPC would need NAT or VPC endpoints (paid); the function only calls AWS APIs
  # checkov:skip=CKV_AWS_272:Code signing requires AWS Signer profiles; the package is built and reviewed in this repository
  function_name    = "${var.name}-auto-response"
  role             = aws_iam_role.responder.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 60
  memory_size      = 128
  kms_key_arn      = var.kms_key_arn

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      APP_LOG_GROUP     = var.app_log_group_name
      NACL_ID           = var.nacl_id
      BLOCKLIST_TABLE   = aws_dynamodb_table.blocklist.name
      ALERT_TOPIC_ARN   = var.alert_topic_arn
      RESPONSE_MODE     = var.mode
      BLOCK_MINUTES     = tostring(var.block_minutes)
      LOOKBACK_MINUTES  = "15"
      NEVER_BLOCK_CIDRS = jsonencode(var.never_block_cidrs)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.responder]
}

# --- Triggers ---
resource "aws_cloudwatch_event_rule" "alarm" {
  name        = "${var.name}-alarm-response"
  description = "Run automated response when a triggering alarm enters ALARM"
  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    resources   = var.trigger_alarm_arns
    detail      = { state = { value = ["ALARM"] } }
  })
}

resource "aws_cloudwatch_event_target" "alarm" {
  rule = aws_cloudwatch_event_rule.alarm.name
  arn  = aws_lambda_function.responder.arn
}

resource "aws_cloudwatch_event_rule" "expire" {
  name                = "${var.name}-expire-blocks"
  description         = "Remove automated IP blocks after their expiry time"
  schedule_expression = "rate(10 minutes)"
}

resource "aws_cloudwatch_event_target" "expire" {
  rule  = aws_cloudwatch_event_rule.expire.name
  arn   = aws_lambda_function.responder.arn
  input = jsonencode({ action = "expire" })
}

resource "aws_lambda_permission" "alarm" {
  statement_id  = "AllowAlarmRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alarm.arn
}

resource "aws_lambda_permission" "expire" {
  statement_id  = "AllowScheduleRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.expire.arn
}
