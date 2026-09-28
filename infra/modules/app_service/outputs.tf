output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "cluster_arn" {
  description = "ECS cluster ARN."
  value       = aws_ecs_cluster.main.arn
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.api.name
}

output "service_arn" {
  description = "ECS service ARN."
  value       = aws_ecs_service.api.id
}

output "task_family" {
  description = "Task definition family."
  value       = aws_ecs_task_definition.api.family
}

output "execution_role_arn" {
  description = "Task execution role ARN."
  value       = aws_iam_role.execution.arn
}

output "app_log_group_name" {
  description = "Application log group name."
  value       = aws_cloudwatch_log_group.api.name
}

output "app_log_group_arn" {
  description = "Application log group ARN."
  value       = aws_cloudwatch_log_group.api.arn
}

output "demo_password_secret_name" {
  description = "Secrets Manager secret holding the demo login password."
  value       = aws_secretsmanager_secret.demo_password.name
}
