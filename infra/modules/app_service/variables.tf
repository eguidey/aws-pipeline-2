variable "name" {
  description = "Resource name prefix."
  type        = string
}

variable "region" {
  description = "AWS region (for the awslogs driver)."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for logs and the application secret."
  type        = string
}

variable "repository_arn" {
  description = "ECR repository the tasks pull from."
  type        = string
}

variable "repository_url" {
  description = "ECR repository URL (for the bootstrap image reference)."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets for the tasks."
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security groups for the tasks."
  type        = list(string)
}

variable "app_port" {
  description = "Container port."
  type        = number
  default     = 8000
}

variable "desired_count" {
  description = "Initial task count (the pipeline scales to 1 after the first deploy)."
  type        = number
  default     = 0
}

variable "cpu" {
  description = "Fargate CPU units."
  type        = string
  default     = "256"
}

variable "memory" {
  description = "Fargate memory (MiB)."
  type        = string
  default     = "512"
}

variable "log_retention_days" {
  description = "App log retention in days."
  type        = number
}
