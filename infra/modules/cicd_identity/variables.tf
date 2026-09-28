variable "name" {
  description = "Resource name prefix."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "github_repository" {
  description = "Repository allowed to deploy, as owner/name."
  type        = string
}

variable "github_owner_id" {
  description = "Numeric GitHub owner ID (repos created after 2026-07-15 use immutable subject claims)."
  type        = string
  default     = ""
}

variable "github_repository_id" {
  description = "Numeric GitHub repository ID (repos created after 2026-07-15 use immutable subject claims)."
  type        = string
  default     = ""
}

variable "github_deploy_branch" {
  description = "Only this branch may assume the deploy role."
  type        = string
}

variable "github_environment" {
  description = "GitHub deployment environment used by the deploy job."
  type        = string
}

variable "create_oidc_provider" {
  description = "Create the account-wide GitHub OIDC provider (false if it already exists)."
  type        = bool
}

variable "repository_arn" {
  description = "ECR repository the pipeline pushes to."
  type        = string
}

variable "cluster_name" {
  description = "ECS cluster the pipeline deploys to."
  type        = string
}

variable "cluster_arn" {
  description = "ARN of that ECS cluster."
  type        = string
}

variable "service_arn" {
  description = "ECS service the pipeline updates."
  type        = string
}

variable "execution_role_arn" {
  description = "Task execution role the pipeline may pass to ECS."
  type        = string
}

variable "deployments_log_group_arn" {
  description = "Log group the pipeline writes deployment records to."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key protecting the deployments log group."
  type        = string
}

variable "allowed_regions" {
  description = "Regions this role may act in (from policy/rules.json); every other region is explicitly denied."
  type        = list(string)
}
