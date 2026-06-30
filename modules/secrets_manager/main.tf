# Minimal Secrets Manager wrapper.
#
# Creates the secret *container* only — the value is populated out-of-band
# (AWS console or `aws secretsmanager put-secret-value`) so credentials never
# live in Terraform state or version control. See the root README's
# "Post-Apply Setup" section.
#
# `ignore_changes = [...]` on the version keeps Terraform from fighting a
# value that was set manually after apply.

resource "aws_secretsmanager_secret" "this" {
  name        = var.name
  description = var.description

  recovery_window_in_days = var.recovery_window_in_days

  tags = {
    "Owning Team" = var.owner
    "Team"        = var.owner
    "Service"     = var.service
  }
}
