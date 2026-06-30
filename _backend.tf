# State backend.
#
# Left as local state by default so `terraform init` works out of the box for
# evaluation. For real use, store state remotely — uncomment and point at an
# S3 bucket + DynamoDB lock table you own. Backend config can't use variables,
# so fill these in literally (or pass with `-backend-config`).
#
# terraform {
#   backend "s3" {
#     bucket         = "REPLACE-ME-tf-state"
#     key            = "aws/org-cloudtrail-alerter/terraform.tfstate"
#     dynamodb_table = "REPLACE-ME-tf-state-lock"
#     region         = "us-east-1"
#     encrypt        = true
#   }
# }
