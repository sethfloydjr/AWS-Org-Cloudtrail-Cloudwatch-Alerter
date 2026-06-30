variable "default_region" {
  type    = string
  default = "us-east-1"
}

variable "service_name" {
  type    = string
  default = "Org-Cloudtrail-Cloudwatch-Alerter"
}

variable "owning_team" {
  type    = string
  default = "SecOps"
}

variable "automation_tf" {
  type    = string
  default = "Terraform"
}

variable "parent_id" {
  description = "The ID of the Organizational Unit (or organization root) under which member accounts are created. Find it with `aws organizations list-roots` (root IDs look like r-abcd)."
  type        = string
  default     = "r-abcd"
}

variable "slack_oncall_group_id" {
  description = "Optional Slack user-group (subteam) ID to @-mention on every alert, e.g. 'S0123456789'. Leave empty to post alerts without a group mention."
  type        = string
  default     = ""
}


####Organization member accounts####

variable "org_prefix" {
  description = "Prefix applied to every member account name, e.g. \"company\" → account \"company-dev\"."
  type        = string
  default     = "company"
}

variable "org_email" {
  description = <<-EOT
    Base email used to derive a unique root email per account via plus-addressing,
    e.g. aws@company.com → aws+company-dev@company.com. AWS requires a unique,
    deliverable email for each account; plus-addressing lets a single mailbox own
    many. Override an individual account with org_accounts[key].email.
  EOT
  type        = string
  default     = "aws@company.com"

  validation {
    condition     = can(regex("^[^@]+@[^@]+$", var.org_email))
    error_message = "org_email must be a single valid email address (local@domain)."
  }
}

variable "org_accounts" {
  description = <<-EOT
    Member accounts to create, keyed by short name (without the org prefix).
    For each entry:
      - name      defaults to "<org_prefix>-<key>"
      - email     defaults to the plus-addressed derivation of var.org_email
      - parent_id defaults to var.parent_id
    Override any field per account; most entries need no overrides at all.
  EOT
  type = map(object({
    name      = optional(string)
    email     = optional(string)
    parent_id = optional(string)
  }))

  # The org-level wiring (FullAWSAccess attachment, IPAM/Config/Macie delegated
  # admins) references these accounts by key, so they must always be present.
  # Fail fast with a clear message instead of a cryptic "Invalid index" later.
  validation {
    condition     = length(setsubtract(["root", "security", "interconnect"], keys(var.org_accounts))) == 0
    error_message = "org_accounts must include the well-known keys: root, security, interconnect."
  }

  default = {
    root                   = {}
    tooling                = {}
    dev                    = {}
    stage                  = {}
    prod                   = {}
    security               = {}
    sandbox                = {}
    qa                     = {}
    datascience            = {}
    backend_test           = {}
    client_test            = {}
    interconnect           = {}
    carrier-interconnect   = {}
    carrier-prod-us-east-1 = {}
    carrier-prod-us-west-2 = {}
    carrier-lab-us-east-1  = {}
  }
}


####CloudTrail related variables####
variable "bucket_name" {
  description = "The name of the S3 bucket to store CloudTrail logs. Must be globally unique."
  type        = string
  default     = "company-org-cloudtrail"
}

variable "s3_key_prefix" {
  description = "The prefix for the S3 bucket keys."
  type        = string
  default     = "company-org"
}

variable "jira_cloud_id" {
  description = "Atlassian Cloud ID for Jira API access. Not a sensitive value — publicly accessible from https://company.atlassian.net/_edge/tenant_info"
  type        = string
  default     = "11111111-1111-1111-1111-111111111111"
}

variable "alert_email" {
  description = "Email address for CloudTrail alert notifications. Sent by Lambda only for real alerts (automation filtered out)."
  type        = string
  default     = "security-alerts@company.com"
}

variable "s3_access_log_bucket" {
  description = "Optional pre-existing S3 bucket (in var.default_region) to receive server access logs for the primary CloudTrail bucket. Leave null to disable S3 access logging."
  type        = string
  default     = null
}

variable "s3_access_log_bucket_west2" {
  description = "Optional pre-existing S3 bucket (in us-west-2) to receive server access logs for the replica CloudTrail bucket. Leave null to disable S3 access logging."
  type        = string
  default     = null
}
