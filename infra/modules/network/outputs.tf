output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = aws_subnet.public[*].id
}

output "api_security_group_id" {
  description = "Security group attached to the API tasks."
  value       = aws_security_group.api.id
}

output "nacl_id" {
  description = "NACL used for automated deny rules."
  value       = aws_network_acl.public.id
}

output "nacl_arn" {
  description = "ARN of the deny-list NACL."
  value       = aws_network_acl.public.arn
}
