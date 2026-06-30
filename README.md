# AWS Org CloudTrail → CloudWatch Security Alerter

Terraform for an AWS Organization's security-monitoring backbone: it manages
the member accounts, stands up an **org-wide CloudTrail**, and runs a
**real-time security-alert pipeline** that turns CloudTrail events into
deduplicated Jira tickets plus Slack and email notifications.

It is one composition with three concerns that share a state file because they
all live in the org-management ("root") account:

1. **Organizations** — member accounts, the org itself, the `FullAWSAccess`
   SCP, and IPAM/Config/Macie delegated-admin wiring.
2. **Org-wide CloudTrail** — a multi-region org trail, S3 storage with a
   cross-region replica, log-file validation, and Insights.
3. **Security alert pipeline** — metric filters + subscription filters on the
   trail's CloudWatch Logs group feed a Python Lambda that classifies events
   and fans out to Jira, Slack, and email.

> The headline is concern #3. Everything interesting in this repo is in how
> CloudTrail events become **exactly one** actionable ticket per incident.

---

## Architecture

```text
CloudTrail (org trail) ──► S3 (us-east-1) ──► S3 replica (us-west-2)
                       └─► CloudWatch Logs group
                                   │
                  ┌────────────────┼─────────────────┐
                  ▼                ▼                 ▼
        metric filters (18)   subscription      1 metric filter
        (dashboards /          filters (2)      feeds 1 alarm
         observability)         │                     │
                                │                     ▼
                                │            alarm: failed-console-logins
                                │            (the only threshold alert, 5+/5min)
                                │                     │
                                │                     ▼
                                │            SNS: cloudtrail_alerts
                                │                     │
                                ▼                     ▼
                          Lambda: cloudtrail-alert-forwarder
                          (router: handle_subscription_event /
                           handle_threshold_alarm)
                  ┌───────────────────┼───────────────────┐
                  ▼                   ▼                   ▼
              Jira (dedup          Slack webhook      SNS: email
              search-then-create)  (#security-alerts) (real alerts only)
```

Two delivery paths, mutually exclusive by design:

| Path | How it fires | Used for |
|---|---|---|
| **Subscription filter (per-event)** | CloudTrail → CW Logs → subscription filter → Lambda, with the full event in the payload | 17 alert types |
| **Threshold alarm (aggregated)** | CW Logs → metric filter → alarm (5+/5min) → SNS → Lambda | `failed-console-logins` only — the aggregation *is* the signal |

---

## Engineering decisions

The parts of this project worth reading the code for.

### 1. Subscription-filter delivery, not alarm-based enrichment

The original design was alarm-only: 18 metric filters fed 18 alarms; the Lambda
received an alarm via SNS and then queried `filter_log_events` to enrich it with
the underlying CloudTrail event. **That enrichment query lost a race with
CloudWatch Logs ingestion lag** on the org-aggregated log group — most alerts
arrived before the event was queryable, so tickets were filed with
`User: N/A, Account: N/A, Source IP: N/A` and on-call stopped trusting them.

The fix was to flip the architecture: a **subscription filter delivers the
matched event directly** in the Lambda payload, eliminating the query and the
race. Tickets now carry full event detail at creation time. The one alarm that
survived is `failed-console-logins`, because "5+ failures in 5 minutes" is an
aggregation that can't be expressed as a per-event filter.

### 2. State-based fingerprint dedup

One action can emit many CloudTrail events (an EKS controller editing 12
security-group rules in a second). To avoid 12 tickets, every event gets a
fingerprint:

```text
fingerprint = sha256(account_id | eventName | actor)[:16]
```

embedded in the ticket description as an HTML comment. Before creating a ticket
the Lambda searches Jira for an **open** issue carrying that fingerprint
(`statusCategory != Done`) and, if found, appends a comment instead of opening a
duplicate.

**Dedup is state-based, not time-based** — there is no time window:

| Scenario | Behavior |
|---|---|
| Ticket open, same action recurs | Comment appended; no new notification |
| Ticket closed, same action recurs | Fresh ticket; new Slack + email |
| Same actor, *different* eventName | Distinct fingerprint → distinct ticket |

Closing the ticket *is* the "incident resolved" signal — more meaningful than an
arbitrary clock. Operationally: triage then close, so the next genuine
recurrence surfaces instead of silently accumulating comments.

Notifications (Slack + email) fire **only when a new ticket is created**.
Comment-only dedup hits are silent; the comment trail is the audit record.

### 3. Concurrency as a blast-radius cap

CW Logs → Lambda subscription delivery is synchronous with **no retry/DLQ for
throttled invokes** — if concurrent invocations exceed the reserved cap, the
event is dropped silently. The cap was originally `5` (set in the alarm era,
~1 fire/min). Under per-event delivery a deploy or cron burst spikes far past
that, so a dropped CRITICAL event would vanish. It's now `50` — comfortably
under the account's 1000 concurrency limit but still bounding blast radius. A
same-invocation fingerprint cache collapses bursts within a single batch, and an
SQS dead-letter queue catches genuinely failed invocations.

### 4. The 1024-char filter-pattern budget

Each subscription filter pattern is capped at 1024 characters, so the alerts are
split across two filters (network vs. everything-else). A few low-volume sources
(`cloudtrail`, `config`, `kms`, `secretsmanager`, `organizations`) are matched by
bare `eventSource` to fit the budget; the Lambda's Python predicates then do the
precise classification. The Terraform pattern and the Python predicate must
agree — see [Adding new alerts](#adding-new-alerts).

### 5. Resilient external calls

Every outbound HTTP call is bounded by a 15s timeout so a hung upstream can't eat
the Lambda budget; the Jira OAuth token and Secrets Manager reads are cached at
module scope (TTL-bounded) so a batched burst doesn't re-auth per event; and the
dedup search has a single short retry for transient timeouts. A dedup-search
failure deliberately raises rather than falling through to "create" — otherwise a
transient API blip would spawn a duplicate ticket on every event.

> The Jira dedup search uses `POST /rest/api/3/search/jql`. Atlassian retired the
> old `GET /rest/api/2/search` endpoint (now HTTP 410), which is exactly the kind
> of vendor change that silently breaks dedup — so the search path is pinned to v3.

For deeper notes — the Lambda's two-entry routing, the same-batch dedup edge
cases, how the architecture evolved, and what *not* to change — see
[DESIGN.md](DESIGN.md).

---

## Alert reference

`Path`: **sub** = subscription filter (per-event); **alarm** = threshold alarm.

**Authentication / Access**

| Alert | Severity | Path | Detects |
|---|---|---|---|
| `root-account-usage` | CRITICAL | sub | Any API call from the root account |
| `console-login-no-mfa` | HIGH | sub | IAM user console login without MFA (SSO logins excluded) |
| `failed-console-logins` | HIGH | alarm | 5+ failed console logins in 5 minutes |

**IAM Changes**

| Alert | Severity | Path | Detects |
|---|---|---|---|
| `iam-user-created` | HIGH | sub | New IAM user created |
| `access-key-creation` | HIGH | sub | IAM access key created |

**Trail / Logging Tampering**

| Alert | Severity | Path | Detects |
|---|---|---|---|
| `cloudtrail-changes` | CRITICAL | sub | CloudTrail stopped, deleted, or modified |
| `cloudwatch-log-tampering` | CRITICAL | sub | Log group or metric filter deleted |
| `config-recorder-changes` | CRITICAL | sub | AWS Config recorder stopped or deleted |

**Network / Infrastructure**

| Alert | Severity | Path | Detects |
|---|---|---|---|
| `security-group-changes` | MEDIUM | sub | Security group rules modified |
| `network-acl-changes` | MEDIUM | sub | Network ACL modified |
| `vpc-changes` | MEDIUM | sub | VPC created, deleted, modified, or peered |
| `route-table-changes` | MEDIUM | sub | Route table modified |

**Data Exfil / Access**

| Alert | Severity | Path | Detects |
|---|---|---|---|
| `s3-bucket-policy-changes` | HIGH | sub | S3 bucket policy modified |
| `s3-public-access-changes` | HIGH | sub | S3 public access block changed |
| `kms-key-changes` | HIGH | sub | KMS key disabled or scheduled for deletion |
| `secrets-manager-changes` | HIGH | sub | Secret deleted or resource policy changed |

**Account Level**

| Alert | Severity | Path | Detects |
|---|---|---|---|
| `organizations-changes` | CRITICAL | sub | Org account added, removed, or invited |
| `scp-changes` | CRITICAL | sub | Service Control Policy changed |

### Automation noise suppression

Role-name regex patterns in `GLOBAL_EXCLUDED_ROLE_PATTERNS`
([cloudwatch_alert_forwarder.py](files/cloudwatch_alert_forwarder.py)) drop
events from automation principals early in the per-event handler — no ticket, no
Slack, no email. Matched against `sessionContext.sessionIssuer.userName` with
`re.search`. Kept in Python rather than the filter pattern because filter
patterns don't support regex, and because `!=` on a possibly-absent nested field
silently drops events and creates blind spots.

Defaults: `^terraform-deploy`, `^gha-runners-role`, `^aws-load-balancer-controller`,
`^company.*Eks-NodeInstanceRole$`.

### Adding new alerts

Two synchronized edits:

1. **[cloudwatch-alerts.tf](cloudwatch-alerts.tf)** — add to `local.cloudtrail_alerts`
   (creates the metric filter via `for_each`) and add the eventName/eventSource
   to one of the subscription filter patterns (mind the 1024-char budget).
2. **[files/cloudwatch_alert_forwarder.py](files/cloudwatch_alert_forwarder.py)** —
   add a `_check_<alert>()` predicate and register it in `ALERT_RULES`, ordered by
   severity descending.

The Python predicate is the precise classifier; the TF pattern is the (possibly
broader) firehose. If the pattern is narrower than the predicate, you'll miss
events.

---

## Repository layout

```text
.
├── accounts.tf            # member accounts (single for_each resource)
├── organization.tf        # org, SCP, delegated admins
├── cloudtrail.tf          # org trail, S3 bucket + cross-region replica
├── cloudwatch-alerts.tf   # metric/subscription filters, alarm, SNS, Lambda, secrets
├── _data.tf               # all aws_iam_policy_document data sources
├── _variables.tf          # inputs (org_accounts map, alerting config, ...)
├── _outputs.tf            # map outputs keyed by account short-name
├── _providers.tf          # provider + version constraints
├── _workspaces.tf         # workspace → deploy-role map (var.workspace_iam_roles)
├── _backend.tf            # state backend (local by default; remote example)
├── files/
│   └── cloudwatch_alert_forwarder.py   # the Lambda
├── modules/
│   └── secrets_manager/   # tiny local module: secret container only
├── tests/
│   └── accounts.tftest.hcl             # native tests, mock providers
└── .github/workflows/terraform.yml     # CI: fmt, validate, test, tflint, trivy, checkov
```

Convention: all `data` blocks live in `_data.tf`; `variable`/`output`/`data`
never appear in resource files.

---

## Usage

### Prerequisites

- Terraform **1.15.7**, AWS provider **>= 6.0.0, < 7.0.0**
- Credentials for the **org-management (root) account**. The provider assumes
  the IAM role mapped to the selected Terraform workspace via
  `var.workspace_iam_roles` ([_workspaces.tf](_workspaces.tf)); select the
  workspace before planning — `terraform workspace select root`.

### Deploy

```bash
cp terraform.tfvars.example terraform.tfvars   # then edit
terraform init
terraform workspace new root   # first time; later: terraform workspace select root
terraform plan
terraform apply
```

> The provider assumes the role mapped to the selected workspace, so you must be
> in the `root` workspace (not `default`) before planning — see
> [_workspaces.tf](_workspaces.tf).

Accounts are **data**: add or remove members by editing the `org_accounts` map
in [_variables.tf](_variables.tf) (or your tfvars) — no per-account resource or
output code to write. Each account's name defaults to `<org_prefix>-<key>` and
its root email to a plus-addressed derivation of `org_email`
(`aws+company-dev@company.com`), both overridable per account.

### Post-apply setup

The Terraform creates secret *containers* only — populate the values once, by
hand, so credentials never touch state or version control:

1. **`secops/cloudwatch-alerts/slack-webhook`** — the Slack incoming webhook URL
   (plain string).
2. **`secops/cloudwatch-alerts/jira-credentials`** — OAuth 2.0 client-credentials
   JSON: `{"client_id":"...","client_secret":"..."}`.
3. **Confirm the SNS email subscription** — AWS emails `var.alert_email` a
   confirmation link that must be clicked.

```bash
aws secretsmanager put-secret-value \
  --secret-id secops/cloudwatch-alerts/slack-webhook \
  --secret-string 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
```

`JIRA_PARENT_KEY` points at the current year's Jira epic; create a new epic at
year-end and update the env var on `aws_lambda_function.alert_forwarder`.

> **Don't set `force_destroy = true`** on either CloudTrail bucket — they are the
> org's audit trail.

---

## Testing & CI

[CI](.github/workflows/terraform.yml) runs on every push and pull request and
needs no AWS credentials — it does `terraform fmt`/`validate`, the native test
suite, `tflint`, `trivy config`, `checkov`, and byte-compiles the Lambda.

The native tests are the interesting part: `terraform test` plans the whole
config against **mock providers**, so the suite creates nothing and runs with
zero credentials. It asserts the account-fan-out logic — name/email derivation,
per-account overrides, and the well-known-account validation
([tests/accounts.tftest.hcl](tests/accounts.tftest.hcl)).

---

## Related

- **[AWS-Athena-SecOps-Queries](https://github.com/sethfloydjr/AWS-Athena-SecOps-Queries)** —
  the downstream companion. It builds an Athena + Glue data lake over the
  CloudTrail logs this stack produces and ships 40+ pre-built SecOps
  investigation queries. The `AthenaSecurityAccountGetObjects` /
  `AthenaSecurityAccountListBucket` cross-account read grants on the CloudTrail
  bucket ([_data.tf](_data.tf)) exist specifically so that stack can query this
  one's logs from the security account.

---

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | 1.15.7 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | >= 2.0.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0.0, < 7.0.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_archive"></a> [archive](#provider\_archive) | 2.8.0 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.52.0 |
| <a name="provider_aws.west2"></a> [aws.west2](#provider\_aws.west2) | 6.52.0 |

## Modules

| Name | Source | Version |
| ---- | ------ | ------- |
| <a name="module_jira_api_secret"></a> [jira\_api\_secret](#module\_jira\_api\_secret) | ./modules/secrets_manager | n/a |
| <a name="module_slack_webhook_secret"></a> [slack\_webhook\_secret](#module\_slack\_webhook\_secret) | ./modules/secrets_manager | n/a |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_cloudtrail.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail) | resource |
| [aws_cloudwatch_log_group.alert_forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_metric_filter.cloudtrail_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_subscription_filter.cloudtrail_alerts_general](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_log_subscription_filter.cloudtrail_alerts_network](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_metric_alarm.cloudtrail_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_iam_organizations_features.org_features](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_organizations_features) | resource |
| [aws_iam_policy.replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.alert_forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.cloudtrail_cloudwatch](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.alert_forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.cloudtrail_cloudwatch](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_lambda_function.alert_forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.sns_invoke](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.subscription_filter_invoke](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_organizations_account.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_account) | resource |
| [aws_organizations_delegated_administrator.config_admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_delegated_administrator) | resource |
| [aws_organizations_delegated_administrator.config_multiaccount_admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_delegated_administrator) | resource |
| [aws_organizations_delegated_administrator.macie_admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_delegated_administrator) | resource |
| [aws_organizations_organization.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_organization) | resource |
| [aws_organizations_policy.FullAWSAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_policy) | resource |
| [aws_organizations_policy_attachment.root_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_policy_attachment) | resource |
| [aws_s3_bucket.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_lifecycle_configuration.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_logging.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging) | resource |
| [aws_s3_bucket_logging.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging) | resource |
| [aws_s3_bucket_ownership_controls.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_ownership_controls.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_public_access_block.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_replication_configuration.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_replication_configuration) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.org_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_s3_bucket_versioning.org_cloudtrail_replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_servicecatalog_organizations_access.root_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/servicecatalog_organizations_access) | resource |
| [aws_sns_topic.cloudtrail_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic.cloudtrail_alerts_email](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.cloudtrail_alerts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.email](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_sns_topic_subscription.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_sqs_queue.alert_forwarder_dlq](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_vpc_ipam_organization_admin_account.vpc_ipam_organization_admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_ipam_organization_admin_account) | resource |
| [archive_file.alert_forwarder](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.alert_forwarder_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.alert_forwarder_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudtrail_cloudwatch_assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudtrail_cloudwatch_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.org_cloudtrail_bucket_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.replication_assume_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.replication_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_alert_email"></a> [alert\_email](#input\_alert\_email) | Email address for CloudTrail alert notifications. Sent by Lambda only for real alerts (automation filtered out). | `string` | `"security-alerts@company.com"` | no |
| <a name="input_automation_tf"></a> [automation\_tf](#input\_automation\_tf) | n/a | `string` | `"Terraform"` | no |
| <a name="input_bucket_name"></a> [bucket\_name](#input\_bucket\_name) | The name of the S3 bucket to store CloudTrail logs. Must be globally unique. | `string` | `"company-org-cloudtrail"` | no |
| <a name="input_default_region"></a> [default\_region](#input\_default\_region) | n/a | `string` | `"us-east-1"` | no |
| <a name="input_jira_cloud_id"></a> [jira\_cloud\_id](#input\_jira\_cloud\_id) | Atlassian Cloud ID for Jira API access. Not a sensitive value — publicly accessible from https://company.atlassian.net/_edge/tenant_info | `string` | `"11111111-1111-1111-1111-111111111111"` | no |
| <a name="input_org_accounts"></a> [org\_accounts](#input\_org\_accounts) | Member accounts to create, keyed by short name (without the org prefix).<br/>For each entry:<br/>  - name      defaults to "<org\_prefix>-<key>"<br/>  - email     defaults to the plus-addressed derivation of var.org\_email<br/>  - parent\_id defaults to var.parent\_id<br/>Override any field per account; most entries need no overrides at all. | <pre>map(object({<br/>    name      = optional(string)<br/>    email     = optional(string)<br/>    parent_id = optional(string)<br/>  }))</pre> | <pre>{<br/>  "backend_test": {},<br/>  "carrier-interconnect": {},<br/>  "carrier-lab-us-east-1": {},<br/>  "carrier-prod-us-east-1": {},<br/>  "carrier-prod-us-west-2": {},<br/>  "client_test": {},<br/>  "datascience": {},<br/>  "dev": {},<br/>  "interconnect": {},<br/>  "prod": {},<br/>  "qa": {},<br/>  "root": {},<br/>  "sandbox": {},<br/>  "security": {},<br/>  "stage": {},<br/>  "tooling": {}<br/>}</pre> | no |
| <a name="input_org_email"></a> [org\_email](#input\_org\_email) | Base email used to derive a unique root email per account via plus-addressing,<br/>e.g. aws@company.com → aws+company-dev@company.com. AWS requires a unique,<br/>deliverable email for each account; plus-addressing lets a single mailbox own<br/>many. Override an individual account with org\_accounts[key].email. | `string` | `"aws@company.com"` | no |
| <a name="input_org_prefix"></a> [org\_prefix](#input\_org\_prefix) | Prefix applied to every member account name, e.g. "company" → account "company-dev". | `string` | `"company"` | no |
| <a name="input_owning_team"></a> [owning\_team](#input\_owning\_team) | n/a | `string` | `"SecOps"` | no |
| <a name="input_parent_id"></a> [parent\_id](#input\_parent\_id) | The ID of the Organizational Unit (or organization root) under which member accounts are created. Find it with `aws organizations list-roots` (root IDs look like r-abcd). | `string` | `"r-abcd"` | no |
| <a name="input_s3_access_log_bucket"></a> [s3\_access\_log\_bucket](#input\_s3\_access\_log\_bucket) | Optional pre-existing S3 bucket (in var.default\_region) to receive server access logs for the primary CloudTrail bucket. Leave null to disable S3 access logging. | `string` | `null` | no |
| <a name="input_s3_access_log_bucket_west2"></a> [s3\_access\_log\_bucket\_west2](#input\_s3\_access\_log\_bucket\_west2) | Optional pre-existing S3 bucket (in us-west-2) to receive server access logs for the replica CloudTrail bucket. Leave null to disable S3 access logging. | `string` | `null` | no |
| <a name="input_s3_key_prefix"></a> [s3\_key\_prefix](#input\_s3\_key\_prefix) | The prefix for the S3 bucket keys. | `string` | `"company-org"` | no |
| <a name="input_service_name"></a> [service\_name](#input\_service\_name) | n/a | `string` | `"Org-Cloudtrail-Cloudwatch-Alerter"` | no |
| <a name="input_slack_oncall_group_id"></a> [slack\_oncall\_group\_id](#input\_slack\_oncall\_group\_id) | Optional Slack user-group (subteam) ID to @-mention on every alert, e.g. 'S0123456789'. Leave empty to post alerts without a group mention. | `string` | `""` | no |
| <a name="input_workspace_iam_roles"></a> [workspace\_iam\_roles](#input\_workspace\_iam\_roles) | Maps each Terraform workspace to the IAM role the AWS provider assumes for that deploy. This stack runs in the org-management ("root") account, so the only workspace is `root`. Select it before plan/apply: terraform workspace select root  Do NOT run in the `default` workspace — it has no role mapping here on purpose. | `map(string)` | <pre>{<br/>  "root": "arn:aws:iam::111111111101:role/TFAdmin"<br/>}</pre> | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_account_arns"></a> [account\_arns](#output\_account\_arns) | Map of account short-name → account ARN. |
| <a name="output_account_emails"></a> [account\_emails](#output\_account\_emails) | Map of account short-name → root email. |
| <a name="output_account_ids"></a> [account\_ids](#output\_account\_ids) | Map of account short-name → AWS account ID. |
| <a name="output_account_names"></a> [account\_names](#output\_account\_names) | Map of account short-name → account name. |
| <a name="output_account_states"></a> [account\_states](#output\_account\_states) | Map of account short-name → account state (ACTIVE, SUSPENDED, ...). |
| <a name="output_organization_arn"></a> [organization\_arn](#output\_organization\_arn) | The ARN of the organization. |
| <a name="output_organization_id"></a> [organization\_id](#output\_organization\_id) | The AWS Organizations organization ID. |
<!-- END_TF_DOCS -->
