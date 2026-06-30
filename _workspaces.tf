# Maps each Terraform workspace to the IAM role the AWS provider assumes for
# that deploy. This stack runs in the org-management ("root") account, so the
# only workspace is `root`. Select it before plan/apply:
#   terraform workspace select root
#
# Do NOT run in the `default` workspace — it has no role mapping here on purpose.
variable "workspace_iam_roles" {
  default = {
    root = "arn:aws:iam::111111111101:role/TFAdmin" # company-root
  }
}
