# Runtime detections from the application's structured JSON logs, plus the
# deployments log that links every alert back to the release that was live.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id       = data.aws_caller_identity.current.account_id
  metric_namespace = "AppSec/${var.name}"

  detections = {
    brute_force = {
      pattern     = "{ $.event_type = \"brute_force_suspected\" }"
      threshold   = 1
      severity    = "HIGH"
      description = "Repeated failed logins from a single source IP (possible credential brute force / MITRE T1110)."
    }
    auth_failure_spike = {
      pattern     = "{ $.event_type = \"auth_failure\" }"
      threshold   = 10
      severity    = "MEDIUM"
      description = "10+ failed logins in 5 minutes across all sources (possible password spraying / T1110.003)."
    }
    injection_attempt = {
      pattern     = "{ $.event_type = \"suspicious_input\" }"
      threshold   = 1
      severity    = "MEDIUM"
      description = "Request matched SQLi / XSS / path traversal / command injection signatures (T1190)."
    }
    rate_limited = {
      pattern     = "{ $.event_type = \"rate_limited\" }"
      threshold   = 20
      severity    = "LOW"
      description = "Client exceeded the rate limit repeatedly (scraping, scanning or application-layer DoS)."
    }
    server_errors = {
      pattern     = "{ $.event_type = \"http_request\" && $.status >= 500 }"
      threshold   = 5
      severity    = "MEDIUM"
      description = "5+ server errors in 5 minutes (application fault or exploitation attempt)."
    }
  }
}

# --- Alerting ---
resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-security-alerts"
  kms_master_key_id = var.kms_key_arn
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AccountOwnerManage"
    actions   = ["sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:Subscribe", "sns:ListSubscriptionsByTopic", "sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }
  statement {
    sid       = "AwsServicesPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email # AWS sends a confirmation email - click the link to start receiving alerts
}

# --- Detections: metric filter + alarm per event type ---
resource "aws_cloudwatch_log_metric_filter" "detections" {
  for_each       = local.detections
  name           = "${var.name}-${each.key}"
  log_group_name = var.app_log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "detections" {
  for_each            = local.detections
  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = "[${each.value.severity}] ${each.value.description}"
  namespace           = local.metric_namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.detections]
}

resource "aws_cloudwatch_query_definition" "hunting" {
  for_each        = fileset(var.hunting_queries_dir, "*.query")
  name            = "${var.name}/${trimsuffix(each.value, ".query")}"
  log_group_names = [var.app_log_group_name]
  query_string    = file("${var.hunting_queries_dir}/${each.value}")
}

# --- The bridge: deployment records written by the pipeline ---
resource "aws_cloudwatch_log_group" "deployments" {
  # checkov:skip=CKV_AWS_338:Retention kept short to minimise cost in a lab environment
  name              = "/${var.name}/deployments"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_query_definition" "correlation" {
  for_each        = fileset(var.correlation_queries_dir, "*.query")
  name            = "${var.name}/correlation/${trimsuffix(each.value, ".query")}"
  log_group_names = [var.app_log_group_name, aws_cloudwatch_log_group.deployments.name]
  query_string    = file("${var.correlation_queries_dir}/${each.value}")
}
