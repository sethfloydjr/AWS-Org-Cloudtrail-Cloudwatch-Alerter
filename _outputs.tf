###############################################################################
# Outputs
#
# The per-account resource is a for_each map, so the outputs are maps keyed by
# the same short name (root, dev, security, ...). Consumers select what they
# need, e.g. module.org.account_ids["security"].
###############################################################################

output "organization_id" {
  description = "The AWS Organizations organization ID."
  value       = aws_organizations_organization.this.id
}

output "organization_arn" {
  description = "The ARN of the organization."
  value       = aws_organizations_organization.this.arn
}

output "account_ids" {
  description = "Map of account short-name → AWS account ID."
  value       = { for k, acct in aws_organizations_account.this : k => acct.id }
}

output "account_arns" {
  description = "Map of account short-name → account ARN."
  value       = { for k, acct in aws_organizations_account.this : k => acct.arn }
}

output "account_names" {
  description = "Map of account short-name → account name."
  value       = { for k, acct in aws_organizations_account.this : k => acct.name }
}

output "account_emails" {
  description = "Map of account short-name → root email."
  value       = { for k, acct in aws_organizations_account.this : k => acct.email }
}

output "account_states" {
  description = "Map of account short-name → account state (ACTIVE, SUSPENDED, ...)."
  value       = { for k, acct in aws_organizations_account.this : k => acct.state }
}
