output "function_name" {
  description = "Auto-response Lambda function name."
  value       = aws_lambda_function.responder.function_name
}

output "blocklist_table" {
  description = "DynamoDB table recording active blocks."
  value       = aws_dynamodb_table.blocklist.name
}
