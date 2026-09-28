variable "name" {
  description = "Resource name prefix."
  type        = string
}

variable "alert_topic_arn" {
  description = "SNS topic for NON_COMPLIANT notifications."
  type        = string
}

variable "alert_email" {
  description = "Email for budget notifications."
  type        = string
}

variable "enable_aws_config" {
  description = "Create an AWS Config recorder and rules (only one recorder is allowed per region)."
  type        = bool
}

variable "enable_guardduty" {
  description = "Enable GuardDuty with ECS Fargate runtime monitoring."
  type        = bool
}

variable "monthly_budget_usd" {
  description = "Budget alert threshold in USD."
  type        = number
}
