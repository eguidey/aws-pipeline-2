variable "name" {
  description = "Resource name prefix."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for the blocklist, Lambda environment and logs."
  type        = string
}

variable "app_log_group_name" {
  description = "Log group queried for evidence."
  type        = string
}

variable "app_log_group_arn" {
  description = "ARN of that log group."
  type        = string
}

variable "nacl_id" {
  description = "NACL where deny rules are added."
  type        = string
}

variable "nacl_arn" {
  description = "ARN of that NACL."
  type        = string
}

variable "alert_topic_arn" {
  description = "SNS topic for response summaries."
  type        = string
}

variable "trigger_alarm_arns" {
  description = "Alarms that trigger the responder."
  type        = list(string)
}

variable "source_file" {
  description = "Path to the Lambda handler source."
  type        = string
}

variable "build_dir" {
  description = "Where to write the Lambda zip."
  type        = string
}

variable "mode" {
  description = "\"block\" or \"notify\" (dry run)."
  type        = string
}

variable "block_minutes" {
  description = "How long a block lasts."
  type        = number
}

variable "never_block_cidrs" {
  description = "CIDRs that are never blocked."
  type        = list(string)
}

variable "log_retention_days" {
  description = "Lambda log retention in days."
  type        = number
}
