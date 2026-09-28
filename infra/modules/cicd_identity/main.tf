# GitHub Actions authenticates to AWS with short-lived OIDC tokens - no stored access keys.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.existing[0].arn

  # Repositories created after 2026-07-15 send an "immutable" subject containing numeric IDs:
  #   repo:OWNER@OWNER_ID/REPO@REPO_ID:...   (older repos send repo:OWNER/REPO:...)
  # The IDs stop a deleted-and-recreated repo with the same name from inheriting this role.
  repo_owner = split("/", var.github_repository)[0]
  repo_name  = split("/", var.github_repository)[1]
  subject_repos = compact([
    "repo:${var.github_repository}",
    var.github_owner_id != "" && var.github_repository_id != "" ? "repo:${local.repo_owner}@${var.github_owner_id}/${local.repo_name}@${var.github_repository_id}" : "",
  ])
  allowed_subjects = flatten([
    for repo in local.subject_repos : [
      "${repo}:ref:refs/heads/${var.github_deploy_branch}",
      "${repo}:environment:${var.github_environment}",
    ]
  ])
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's certificate itself; these values are kept for older provider versions.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

data "aws_iam_openid_connect_provider" "existing" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "assume" {
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
    # Only this repository's deploy branch or protected environment - never forks, PRs or other branches.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.allowed_subjects
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "${var.name}-github-deploy"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # no resource-level support for this action
  }
  statement {
    sid = "PushAndSignThisRepositoryOnly"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages",
      "ecr:DescribeImageScanFindings", "ecr:ListImages", "ecr:GetDownloadUrlForLayer",
    ]
    resources = [var.repository_arn]
  }
  statement {
    sid       = "TaskDefinitions"
    actions   = ["ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition"]
    resources = ["*"] # these actions do not support resource-level permissions
  }
  statement {
    sid       = "DeployThisServiceOnly"
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = [var.service_arn]
  }
  statement {
    sid       = "SmokeTestDescribeTasksInThisClusterOnly"
    actions   = ["ecs:DescribeTasks"]
    resources = ["arn:${local.partition}:ecs:${var.region}:${local.account_id}:task/${var.cluster_name}/*"]
  }
  statement {
    sid       = "SmokeTestListTasksInThisClusterOnly"
    actions   = ["ecs:ListTasks"]
    resources = ["arn:${local.partition}:ecs:${var.region}:${local.account_id}:container-instance/${var.cluster_name}/*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.cluster_arn]
    }
  }
  statement {
    sid       = "SmokeTestFindTaskPublicIp"
    actions   = ["ec2:DescribeNetworkInterfaces"]
    resources = ["*"] # read-only; EC2 Describe* actions have no resource-level support
  }
  statement {
    sid       = "PassOnlyTheExecutionRoleToEcs"
    actions   = ["iam:PassRole"]
    resources = [var.execution_role_arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
  statement {
    sid       = "WriteDeploymentRecords"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${var.deployments_log_group_arn}:*"]
  }
  statement {
    sid       = "EncryptDeploymentRecords"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
  # Preventive region lock (the AWS equivalent of an Azure Policy "allowed locations" deny):
  # even a future over-broad Allow above cannot act outside the approved regions.
  statement {
    sid         = "DenyOutsideApprovedRegions"
    effect      = "Deny"
    not_actions = ["iam:*", "sts:*"] # global services are addressed via us-east-1 and must not be caught here
    resources   = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "least-privilege-deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
