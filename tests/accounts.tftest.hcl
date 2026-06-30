# Native Terraform tests for the org-account fan-out logic.
#
# Uses mock providers so the whole suite runs with NO AWS credentials and
# creates nothing — `terraform test` plans the config against mocked AWS
# responses and asserts on the values our own code derives (account names,
# plus-addressed emails, parent IDs, variable validation).

# The provider assumes var.workspace_iam_roles[terraform.workspace]; tests run
# in the `default` workspace, so give that key a (mock-ignored) role ARN.
variables {
  workspace_iam_roles = {
    default = "arn:aws:iam::111111111101:role/TFAdmin"
  }
}

# aws_iam_policy_document data sources feed assume_role_policy / bucket policy
# arguments that validate their input as JSON at plan time. The default mock
# returns a placeholder string that fails that validation, so give every
# policy-document data source a valid (empty) IAM policy.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
  # Several resources validate the caller account ID as exactly 12 digits.
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:root"
      user_id    = "AIDAEXAMPLE"
    }
  }
}
mock_provider "aws" {
  alias = "west2"
}

run "account_name_and_email_derive_from_prefix" {
  command = plan

  # Keep the full default account set (org-level wiring needs root/security/
  # interconnect); only change the prefix/email/parent so we can assert on the
  # derived values.
  variables {
    org_prefix = "acme"
    org_email  = "aws@acme.test"
    parent_id  = "r-test"
  }

  assert {
    condition     = aws_organizations_account.this["dev"].name == "acme-dev"
    error_message = "Account name should default to <org_prefix>-<key>."
  }

  assert {
    condition     = aws_organizations_account.this["dev"].email == "aws+acme-dev@acme.test"
    error_message = "Account email should be plus-addressed from org_email."
  }

  assert {
    condition     = aws_organizations_account.this["dev"].parent_id == "r-test"
    error_message = "Account parent_id should default to var.parent_id."
  }
}

run "per_account_overrides_win" {
  command = plan

  # Include the well-known required keys plus one fully-overridden account.
  variables {
    org_prefix = "acme"
    org_email  = "aws@acme.test"
    org_accounts = {
      root         = {}
      security     = {}
      interconnect = {}
      special = {
        name      = "totally-custom-name"
        email     = "custom@acme.test"
        parent_id = "ou-ab12-cd34ef56"
      }
    }
  }

  assert {
    condition     = aws_organizations_account.this["special"].name == "totally-custom-name"
    error_message = "Explicit name override should win over the derived default."
  }

  assert {
    condition     = aws_organizations_account.this["special"].email == "custom@acme.test"
    error_message = "Explicit email override should win over plus-addressing."
  }

  assert {
    condition     = aws_organizations_account.this["special"].parent_id == "ou-ab12-cd34ef56"
    error_message = "Explicit parent_id override should win over var.parent_id."
  }
}

run "all_default_accounts_are_created" {
  command = plan

  assert {
    condition     = length(aws_organizations_account.this) == 16
    error_message = "The default org_accounts map should produce 16 member accounts."
  }
}

run "rejects_malformed_org_email" {
  command = plan

  variables {
    org_email = "not-an-email"
  }

  expect_failures = [
    var.org_email,
  ]
}

run "rejects_org_accounts_missing_required_keys" {
  command = plan

  variables {
    org_accounts = {
      dev = {}
    }
  }

  expect_failures = [
    var.org_accounts,
  ]
}
