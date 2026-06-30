terraform {
  required_version = "1.15.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0.0"
    }
  }
}


# Primary provider — the org-management ("root") account, us-east-1.
# The deploy role is selected per Terraform workspace via var.workspace_iam_roles
# (see _workspaces.tf). Select the workspace before plan/apply, e.g.
# `terraform workspace select root`.
provider "aws" {
  region = var.default_region
  assume_role {
    role_arn = var.workspace_iam_roles[terraform.workspace]
  }
  default_tags {
    tags = {
      "Service_Name"        = var.service_name
      "Owning_Team"         = var.owning_team
      "Automation"          = var.automation_tf
      "Terraform Base Path" = "path/to/where/you/put/the/code"
    }
  }
}

# Secondary provider — us-west-2, used for the CloudTrail S3 replica bucket.
provider "aws" {
  alias  = "west2"
  region = "us-west-2"
  assume_role {
    role_arn = var.workspace_iam_roles[terraform.workspace]
  }
  default_tags {
    tags = {
      "Service_Name"        = var.service_name
      "Owning_Team"         = var.owning_team
      "Automation"          = var.automation_tf
      "Terraform Base Path" = "path/to/where/you/put/the/code"
    }
  }
}
