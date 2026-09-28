variable "name" {
  description = "Resource name prefix."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for the alert topic and deployments log."
  type        = string
}

variable "alert_email" {
  description = "Email subscribed to security alerts."
  type        = string
}

variable "app_log_group_name" {
  description = "Application log group the detections read."
  type        = string
}

variable "log_retention_days" {
  description = "Deployments log retention in days."
  type        = number
}

variable "hunting_queries_dir" {
  description = "Folder of *.query files run against the app log group."
  type        = string
}

variable "correlation_queries_dir" {
  description = "Folder of *.query files run across the app AND deployments log groups."
  type        = string
}
