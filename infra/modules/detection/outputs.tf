output "alert_topic_arn" {
  description = "SNS topic that emails security alerts."
  value       = aws_sns_topic.alerts.arn
}

output "alarm_arns" {
  description = "Alarm ARNs keyed by detection name."
  value       = { for k, a in aws_cloudwatch_metric_alarm.detections : k => a.arn }
}

output "deployments_log_group_name" {
  description = "Log group the pipeline writes deployment records to."
  value       = aws_cloudwatch_log_group.deployments.name
}

output "deployments_log_group_arn" {
  description = "ARN of the deployments log group."
  value       = aws_cloudwatch_log_group.deployments.arn
}
