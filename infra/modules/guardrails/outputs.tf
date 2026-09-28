output "config_rule_names" {
  description = "AWS Config guardrail rules."
  value       = [for r in aws_config_config_rule.guardrails : r.name]
}
