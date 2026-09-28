# ---------------------------------------------------------------- environment
variable "environment" {
  description = "Environment name. Used for tagging."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "dev"], var.environment)
    error_message = "environment must be \"prod\" or \"dev\"."
  }
}

variable "region" {
  description = "AWS region to deploy into. Must be listed in policy/rules.json (allowed_regions)."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = contains(jsondecode(file("${path.module}/../policy/rules.json")).allowed_regions, var.region)
    error_message = "This region is not allowed by policy/rules.json (allowed_regions). Change the policy file through review if you really need it."
  }
}

variable "project_name" {
  description = "Prefix used for every resource name. Use a different value per environment."
  type        = string
  default     = "aws-pipeline-2"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.project_name))
    error_message = "Use 3-25 lowercase letters, numbers or hyphens, starting with a letter."
  }
}

variable "owner" {
  description = "Owner tag applied to all resources."
  type        = string
  default     = "ian-guidry"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16" # different from the original deployment (10.40/16) so the two never overlap
}

# ---------------------------------------------------------------- GitHub / CI-CD
variable "github_repository" {
  description = "GitHub repository allowed to deploy, in owner/name form."
  type        = string
  default     = "eguidey/aws-pipeline-2"
}

variable "github_owner_id" {
  description = "Numeric GitHub user/org ID. Required for repos created after 2026-07-15 (immutable OIDC subject claims)."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[0-9]*$", var.github_owner_id))
    error_message = "github_owner_id must be digits only."
  }
}

variable "github_repository_id" {
  description = "Numeric GitHub repository ID. Required for repos created after 2026-07-15 (immutable OIDC subject claims)."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[0-9]*$", var.github_repository_id))
    error_message = "github_repository_id must be digits only."
  }
}

variable "github_deploy_branch" {
  description = "Only this branch may assume the deploy role."
  type        = string
  default     = "main"
}

variable "github_environment" {
  description = "GitHub deployment environment used by the deploy job."
  type        = string
  default     = "production"
}

variable "create_github_oidc_provider" {
  description = "Create the account-wide GitHub OIDC provider here. Leave false: infra/bootstrap owns it, so `terraform destroy` on this stack can never cut CI off from AWS."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------- application
variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed to reach the API. Use [\"<your-ip>/32\"] to keep it private."
  type        = list(string)
  sensitive   = true # keeps it out of plan output (Actions logs are public on a public repo)
  default     = ["0.0.0.0/0"]
}

variable "task_cpu" {
  description = "Fargate CPU units for the API task. Capped by policy/rules.json (fargate.max_cpu)."
  type        = number
  default     = 256

  validation {
    condition = (
      contains(keys(jsondecode(file("${path.module}/../policy/rules.json")).fargate.valid_sizes), tostring(var.task_cpu)) &&
      var.task_cpu <= jsondecode(file("${path.module}/../policy/rules.json")).fargate.max_cpu
    )
    error_message = "task_cpu must be a Fargate size (256, 512, 1024...) no larger than fargate.max_cpu in policy/rules.json."
  }
}

variable "task_memory" {
  description = "Fargate memory (MiB) for the API task. Must be a valid pairing with task_cpu."
  type        = number
  default     = 512

  validation {
    condition     = contains(lookup(jsondecode(file("${path.module}/../policy/rules.json")).fargate.valid_sizes, tostring(var.task_cpu), []), var.task_memory)
    error_message = "task_memory is not valid with this task_cpu (e.g. cpu 256 allows 512, 1024 or 2048). See fargate.valid_sizes in policy/rules.json."
  }
}

variable "desired_count" {
  description = "Initial task count. Starts at 0; the pipeline scales to 1 after the first image push."
  type        = number
  default     = 0
}

variable "log_retention_days" {
  description = "How long to keep application, flow and Lambda logs."
  type        = number
  default     = 30
}

# ---------------------------------------------------------------- alerting & response
variable "alert_email" {
  description = "Email that receives security alerts, guardrail findings and budget warnings."
  type        = string
  sensitive   = true # keeps it out of plan output (Actions logs are public on a public repo)

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "Provide a valid email address."
  }
}

variable "auto_response_mode" {
  description = "\"block\" adds NACL deny rules for offending IPs; \"notify\" only emails what it would block."
  type        = string
  default     = "block"
  validation {
    condition     = contains(["block", "notify"], var.auto_response_mode)
    error_message = "auto_response_mode must be \"block\" or \"notify\"."
  }
}

variable "block_minutes" {
  description = "How long an automated block lasts before it is removed."
  type        = number
  default     = 30
}

variable "never_block_cidrs" {
  description = "CIDRs the responder must never block."
  type        = list(string)
  sensitive   = true # keeps it out of plan output (Actions logs are public on a public repo)
  default     = []
}

# ---------------------------------------------------------------- guardrails & cost
variable "enable_aws_config" {
  description = "Create an AWS Config recorder and guardrail rules. Only one recorder is allowed per region."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty with ECS Fargate runtime monitoring (30-day free trial, then paid)."
  type        = bool
  default     = false
}

variable "monthly_budget_usd" {
  description = "Email when forecast spend exceeds this amount."
  type        = number
  default     = 10
}
