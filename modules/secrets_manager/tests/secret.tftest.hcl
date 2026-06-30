# Native tests for the secrets_manager module. Mock provider → no AWS calls.

mock_provider "aws" {}

run "creates_named_secret_with_tags" {
  command = plan

  variables {
    name        = "secops/cloudwatch-alerts/jira-credentials"
    description = "Jira API credentials"
    owner       = "SECOPS"
    service     = "cloudwatch-alerts"
  }

  assert {
    condition     = aws_secretsmanager_secret.this.name == "secops/cloudwatch-alerts/jira-credentials"
    error_message = "Secret name should pass through unchanged."
  }

  assert {
    condition     = aws_secretsmanager_secret.this.tags["Service"] == "cloudwatch-alerts"
    error_message = "Service tag should be set from var.service."
  }

  assert {
    condition     = aws_secretsmanager_secret.this.tags["Owning Team"] == "SECOPS"
    error_message = "Owning Team tag should be set from var.owner."
  }
}
