# secrets_manager

Minimal wrapper around `aws_secretsmanager_secret` that creates the secret
**container** only — the value is populated out-of-band (AWS console or
`aws secretsmanager put-secret-value`) so credentials never live in Terraform
state or version control.

## Usage

```hcl
module "jira_api_secret" {
  source      = "./modules/secrets_manager"
  name        = "secops/cloudwatch-alerts/jira-credentials"
  description = "Jira API credentials for CloudTrail alert ticket creation"
  owner       = "SECOPS"
  service     = "cloudwatch-alerts"
}

# Consumer reads the ARN, e.g. to grant a Lambda secretsmanager:GetSecretValue
output "arn" {
  value = module.jira_api_secret.secret_arn
}
```

After `terraform apply`, set the value:

```bash
aws secretsmanager put-secret-value \
  --secret-id secops/cloudwatch-alerts/jira-credentials \
  --secret-string '{"client_id":"...","client_secret":"..."}'
```

---

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0.0, < 7.0.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.52.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_secretsmanager_secret.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_description"></a> [description](#input\_description) | Human-readable description of what the secret holds. | `string` | `""` | no |
| <a name="input_name"></a> [name](#input\_name) | Name (path) of the secret, e.g. secops/cloudwatch-alerts/jira-credentials. | `string` | n/a | yes |
| <a name="input_owner"></a> [owner](#input\_owner) | Owning team, applied as a tag. | `string` | `"SECOPS"` | no |
| <a name="input_recovery_window_in_days"></a> [recovery\_window\_in\_days](#input\_recovery\_window\_in\_days) | Days AWS retains the secret after deletion before permanent removal. Set to 0 for immediate deletion (handy in non-prod). | `number` | `30` | no |
| <a name="input_service"></a> [service](#input\_service) | Service this secret belongs to, applied as a tag. | `string` | `""` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_secret_arn"></a> [secret\_arn](#output\_secret\_arn) | ARN of the created secret. |
| <a name="output_secret_name"></a> [secret\_name](#output\_secret\_name) | Name (path) of the created secret. |
<!-- END_TF_DOCS -->
