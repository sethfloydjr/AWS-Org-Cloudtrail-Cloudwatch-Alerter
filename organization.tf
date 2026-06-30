resource "aws_organizations_organization" "this" {
  aws_service_access_principals = [
    "config.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "ram.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "sso.amazonaws.com",
    "account.amazonaws.com",
    "compute-optimizer.amazonaws.com",
    "guardduty.amazonaws.com",
    "reporting.trustedadvisor.amazonaws.com",
    "storage-lens.s3.amazonaws.com",
    "health.amazonaws.com",
    "cost-optimization-hub.bcm.amazonaws.com",
    "ipam.amazonaws.com",
    "iam.amazonaws.com",
    "servicecatalog.amazonaws.com",
    "macie.amazonaws.com",
    "inspector2.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
    "securityhub.amazonaws.com"
  ]
  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY"
  ]
  feature_set = "ALL"
  lifecycle {
    ignore_changes = [enabled_policy_types]
  }
}

resource "aws_iam_organizations_features" "org_features" {
  enabled_features = [
    "RootCredentialsManagement",
    "RootSessions"
  ]
}


/*
Manages Service Catalog AWS Organizations Access, a portfolio sharing feature through AWS Organizations. This allows Service Catalog to receive updates on your organization in order to sync your shares with the current structure. This resource will prompt AWS to set organizations:EnableAWSServiceAccess on your behalf so that your shares can be in sync with any changes in your AWS Organizations structure.
*/
resource "aws_servicecatalog_organizations_access" "root_account" {
  enabled = "true"
}



####################################################################################
# This policy has been enabled since we now want the root user of the root account to have sole root access to all other accounts that we have. 
# This is being done because AWS now requires all root users to have MFA enabled. 
# This method will be easier to manage and enforce.
# For more info see the following helpful pages:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_policy
# https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_inheritance_auth.html
####################################################################################


resource "aws_organizations_policy" "FullAWSAccess" {
  description = "Allows access to every operation"
  name        = "FullAWSAccess"
  type        = "SERVICE_CONTROL_POLICY"
  content     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }
}
EOF
}

resource "aws_organizations_policy_attachment" "root_account" {
  policy_id = aws_organizations_policy.FullAWSAccess.id
  target_id = aws_organizations_account.this["root"].id
}


# Sets the IPAM administrator account - TOOLING
resource "aws_vpc_ipam_organization_admin_account" "vpc_ipam_organization_admin" {
  delegated_admin_account_id = aws_organizations_account.this["interconnect"].id
}


# Sets the Security account as the delegated administrator for AWS Config
resource "aws_organizations_delegated_administrator" "config_admin" {
  depends_on        = [aws_organizations_organization.this]
  account_id        = aws_organizations_account.this["security"].id #Security Account
  service_principal = "config.amazonaws.com"
}

# Sets the Security account as the delegated administrator for AWS Config-MultiAccount
resource "aws_organizations_delegated_administrator" "config_multiaccount_admin" {
  depends_on        = [aws_organizations_organization.this]
  account_id        = aws_organizations_account.this["security"].id #Security Account
  service_principal = "config-multiaccountsetup.amazonaws.com"
}

# Sets the Security account as the delegated administrator for AWS Macie
resource "aws_organizations_delegated_administrator" "macie_admin" {
  depends_on        = [aws_organizations_organization.this]
  account_id        = aws_organizations_account.this["security"].id #Security Account
  service_principal = "macie.amazonaws.com"
}
