##########################################################################
# Organization member accounts.
#
# One resource, fanned out across var.org_accounts with for_each so the set
# of accounts is data, not copy-pasted blocks. Adding an account = adding a
# map entry in _variables.tf (no new resource/output code, no codegen script).
#
# for_each (not count) keeps each account addressed by its stable short name
# (aws_organizations_account.this["dev"]), so removing one account never
# churns the others' state addresses.
#
# Note: deleting one of these resources does NOT delete the AWS account — it
# only detaches it from the organization and drops it from state.
##########################################################################

locals {
  _org_email_local  = split("@", var.org_email)[0]
  _org_email_domain = split("@", var.org_email)[1]
}

resource "aws_organizations_account" "this" {
  for_each = var.org_accounts

  name = coalesce(each.value.name, "${var.org_prefix}-${each.key}")
  email = coalesce(
    each.value.email,
    "${local._org_email_local}+${var.org_prefix}-${each.key}@${local._org_email_domain}",
  )
  parent_id = coalesce(each.value.parent_id, var.parent_id)
}
