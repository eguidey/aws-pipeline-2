output "deploy_role_arn" {
  description = "Role GitHub Actions assumes via OIDC."
  value       = aws_iam_role.deploy.arn
}

output "allowed_subjects" {
  description = "GitHub OIDC subjects trusted by the deploy role."
  value       = local.allowed_subjects
}
