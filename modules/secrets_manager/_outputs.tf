output "secret_arn" {
  description = "ARN of the created secret."
  value       = aws_secretsmanager_secret.this.arn
}

output "secret_name" {
  description = "Name (path) of the created secret."
  value       = aws_secretsmanager_secret.this.name
}
