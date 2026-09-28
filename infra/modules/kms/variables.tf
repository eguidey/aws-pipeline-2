variable "name" {
  description = "Resource name prefix."
  type        = string
}

variable "region" {
  description = "AWS region (used to scope the CloudWatch Logs service principal)."
  type        = string
}
