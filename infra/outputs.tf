# The first six map directly to the GitHub repository variables the pipeline needs.

output "aws_region" {
  description = "GitHub variable AWS_REGION."
  value       = var.region
}

output "github_deploy_role_arn" {
  description = "GitHub variable AWS_DEPLOY_ROLE_ARN."
  value       = module.cicd_identity.deploy_role_arn
}

output "ecr_repository_name" {
  description = "GitHub variable ECR_REPOSITORY."
  value       = module.registry.repository_name
}

output "ecs_cluster_name" {
  description = "GitHub variable ECS_CLUSTER."
  value       = module.app_service.cluster_name
}

output "ecs_service_name" {
  description = "GitHub variable ECS_SERVICE."
  value       = module.app_service.service_name
}

output "ecs_task_family" {
  description = "GitHub variable ECS_TASK_FAMILY."
  value       = module.app_service.task_family
}

output "app_log_group" {
  description = "Application security telemetry."
  value       = module.app_service.app_log_group_name
}

output "deployments_log_group" {
  description = "Deployment records written by the pipeline (the CI/CD-to-detection bridge)."
  value       = module.detection.deployments_log_group_name
}

output "demo_password_secret" {
  description = "Secrets Manager secret holding the /api/login demo password."
  value       = module.app_service.demo_password_secret_name
}

output "response_nacl_id" {
  description = "NACL where the responder adds deny rules. Unblock: aws ec2 delete-network-acl-entry --network-acl-id <id> --ingress --rule-number <N>"
  value       = module.network.nacl_id
}

output "auto_response_function" {
  description = "Lambda that responds to brute-force and injection alarms."
  value       = module.response.function_name
}

output "trusted_github_subjects" {
  description = "GitHub OIDC subjects the deploy role accepts (check this if a deploy is denied)."
  value       = module.cicd_identity.allowed_subjects
}

output "guardrail_rules" {
  description = "AWS Config rules evaluating this environment."
  value       = module.guardrails.config_rule_names
}
