# ---------------------------------------------------------------------------
# GitHub Actions identities for running Terraform itself (.github/workflows/infra.yml).
#
# These live in the bootstrap stack - not the app stack - for the same reason the Azure
# version bootstraps its GitHub identity by hand: `terraform destroy` on the app must never
# delete the credentials the pipeline needs to rebuild it. The account-wide GitHub OIDC
# provider lives here too, so the app stack only looks it up.
#
#   terraform-plan   pull requests      read-only; runs plan + the policy gate
#   terraform-apply  `infrastructure`   GitHub environment (required reviewers); runs apply
# ---------------------------------------------------------------------------

variable "github_repository" {
  description = "Repository allowed to run Terraform, in owner/name form."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Use owner/name form, e.g. your-user/aws-appsec-pipeline."
  }
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

variable "terraform_environment" {
  description = "GitHub environment the apply job uses. Protect it with required reviewers and a main-only branch rule."
  type        = string
  default     = "infrastructure"
}

variable "create_github_oidc_provider" {
  description = "Create the account-wide GitHub OIDC provider. Set false only if something outside this project already created it."
  type        = bool
  default     = true
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  policy     = jsondecode(file("${path.module}/../../policy/rules.json"))

  oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.existing[0].arn

  # Same subject handling as modules/cicd_identity: legacy and immutable (ID-based) forms.
  repo_owner = split("/", var.github_repository)[0]
  repo_name  = split("/", var.github_repository)[1]
  subject_repos = compact([
    "repo:${var.github_repository}",
    var.github_owner_id != "" && var.github_repository_id != "" ? "repo:${local.repo_owner}@${var.github_owner_id}/${local.repo_name}@${var.github_repository_id}" : "",
  ])
  plan_subjects  = [for r in local.subject_repos : "${r}:pull_request"]
  apply_subjects = [for r in local.subject_repos : "${r}:environment:${var.terraform_environment}"]

  plan_role_name  = "${var.project_name}-terraform-plan"
  apply_role_name = "${var.project_name}-terraform-apply"

  # Global services are addressed through us-east-1 and must be exempt from the region lock.
  global_services = ["iam:*", "sts:*", "organizations:*", "budgets:*", "ce:*", "cloudfront:*", "route53:*", "support:*", "health:*", "account:*"]
}

data "aws_partition" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's certificate itself; these values are kept for older provider versions.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]

  lifecycle {
    prevent_destroy = true # every pipeline in the account depends on it
  }
}

data "aws_iam_openid_connect_provider" "existing" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "trust" {
  for_each = { plan = local.plan_subjects, apply = local.apply_subjects }
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = each.value
    }
  }
}

# ------------------------------------------------------------------ plan role (pull requests)
resource "aws_iam_role" "terraform_plan" {
  name                 = local.plan_role_name
  description          = "GitHub Actions: terraform plan + policy gate on pull requests (read-only)"
  assume_role_policy   = data.aws_iam_policy_document.trust["plan"].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.terraform_plan.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_extra" {
  statement {
    sid       = "ReadStateList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }
  statement {
    sid       = "ReadStateAndTakeLock"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/${var.project_name}/*"] # PutObject/DeleteObject only ever touch *.tflock
  }
  statement {
    sid       = "RefreshTheAppSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:${local.partition}:secretsmanager:*:${local.account_id}:secret:${var.project_name}*"]
  }
  statement {
    sid       = "DecryptTheAppSecretViaSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = ["arn:${local.partition}:kms:*:${local.account_id}:key/*"]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["secretsmanager.*.amazonaws.com"]
    }
  }
  statement {
    sid         = "DenyOutsideApprovedRegions"
    effect      = "Deny"
    not_actions = local.global_services
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.policy.allowed_regions
    }
  }
}

resource "aws_iam_role_policy" "plan_extra" {
  name   = "state-access-and-region-lock"
  role   = aws_iam_role.terraform_plan.id
  policy = data.aws_iam_policy_document.plan_extra.json
}

# ------------------------------------------------------------------ apply role (protected environment)
resource "aws_iam_role" "terraform_apply" {
  name                 = local.apply_role_name
  description          = "GitHub Actions: terraform apply from the protected ${var.terraform_environment} environment"
  assume_role_policy   = data.aws_iam_policy_document.trust["apply"].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "apply_admin" {
  # checkov:skip=CKV_AWS_274:Terraform creates IAM roles, KMS keys and AWS Config; guarded by explicit denies below, a protected GitHub environment and the policy gate
  role       = aws_iam_role.terraform_apply.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AdministratorAccess"
}

# Explicit denies win over AdministratorAccess. They are the guardrails Azure Policy provides at
# the control plane: approved regions only, no long-lived credentials, and no tampering with the
# identity or state the pipeline itself depends on.
data "aws_iam_policy_document" "apply_guardrails" {
  statement {
    sid         = "DenyOutsideApprovedRegions"
    effect      = "Deny"
    not_actions = local.global_services
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.policy.allowed_regions
    }
  }
  statement {
    sid       = "DenyLongLivedCredentials"
    effect    = "Deny"
    actions   = ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
    resources = ["*"]
  }
  statement {
    sid = "DenyChangingOrLendingThePipelineRoles"
    # PassRole is denied too, so Terraform cannot hand these roles to a Lambda or instance.
    effect  = "Deny"
    actions = ["iam:Update*", "iam:Put*", "iam:Delete*", "iam:Attach*", "iam:Detach*", "iam:Tag*", "iam:Untag*", "iam:PassRole"]
    resources = [
      "arn:${local.partition}:iam::${local.account_id}:role/${local.plan_role_name}",
      "arn:${local.partition}:iam::${local.account_id}:role/${local.apply_role_name}",
    ]
  }
  statement {
    sid    = "DenyChangingTheOidcProvider"
    effect = "Deny" # reads stay allowed: the app stack looks the provider up
    actions = [
      "iam:DeleteOpenIDConnectProvider", "iam:UpdateOpenIDConnectProviderThumbprint",
      "iam:AddClientIDToOpenIDConnectProvider", "iam:RemoveClientIDFromOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider", "iam:UntagOpenIDConnectProvider",
    ]
    resources = [local.oidc_provider_arn]
  }
  statement {
    sid    = "DenyWeakeningTheStateBucket"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy", "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration", "s3:PutBucketPublicAccessBlock",
      "s3:DeleteObjectVersion",
    ]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
}

resource "aws_iam_role_policy" "apply_guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.terraform_apply.id
  policy = data.aws_iam_policy_document.apply_guardrails.json
}

# ------------------------------------------------------------------ outputs
output "terraform_plan_role_arn" {
  description = "GitHub variable TF_PLAN_ROLE_ARN."
  value       = aws_iam_role.terraform_plan.arn
}

output "terraform_apply_role_arn" {
  description = "GitHub variable TF_APPLY_ROLE_ARN."
  value       = aws_iam_role.terraform_apply.arn
}

output "github_oidc_provider_arn" {
  description = "Account-wide GitHub OIDC provider (owned by this stack)."
  value       = local.oidc_provider_arn
}

output "trusted_terraform_subjects" {
  description = "GitHub OIDC subjects the Terraform roles accept (check this if a run is denied)."
  value       = { plan = local.plan_subjects, apply = local.apply_subjects }
}
