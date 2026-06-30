# CloudWatch Alert Pipeline for Org-wide CloudTrail Events
#
# These alerts monitor the CloudTrail CloudWatch Log Group for security-critical
# events across all accounts in the organization.
#
# TWO DELIVERY PATHS (split intentionally — see DESIGN.md for rationale):
#
# 1. SUBSCRIPTION FILTER (per-event, no race):
#    CloudTrail → CW Logs → subscription filter → Lambda (per-event payload)
#    Used for 17 of 18 alert types (everything with threshold = 1).
#    The Lambda receives the matched event directly — no enrichment query lag.
#
# 2. THRESHOLD ALARM (aggregated count, kept for failed-console-logins ONLY):
#    CloudTrail → CW Logs → metric filter → alarm (5+ in 5min) → SNS → Lambda
#    Used ONLY for failed-console-logins, where the "5+ in 5min" aggregation
#    IS the signal. Routing this through the subscription filter would lose
#    the threshold semantic.
#
# Invariant: failed-console-logins is excluded from the subscription filter
# pattern so the same event is never double-ticketed. The Python router in
# files/cloudwatch_alert_forwarder.py distinguishes the two payload shapes
# (awslogs.data → subscription path; Records[].Sns → alarm path).
#
# All 18 metric filters are retained for dashboarding and historical metric
# data, even though 17 of them no longer feed alarms.


##############################
# LOCALS - ALERT DEFINITIONS
##############################

locals {
  cloudtrail_alerts = {

    ##############################################
    # Authentication / Access
    ##############################################

    # Detects any API call made by the root account. Root should never be used for
    # day-to-day operations. Any root activity outside of break-glass scenarios
    # is a potential compromise or policy violation.
    "root-account-usage" = {
      description    = "Root account API activity detected"
      filter_pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      metric_name    = "RootAccountUsage"
      threshold      = 1
      period         = 300
      severity       = "CRITICAL"
    }

    # Detects successful IAM user console logins where MFA was not used. Excludes
    # federated/SSO logins (Okta) since MFA is handled by the identity provider.
    # Only IAM user direct logins without MFA are flagged.
    "console-login-no-mfa" = {
      description    = "IAM user console login without MFA"
      filter_pattern = "{ $.eventName = \"ConsoleLogin\" && $.additionalEventData.MFAUsed != \"Yes\" && $.responseElements.ConsoleLogin = \"Success\" && $.userIdentity.type = \"IAMUser\" }"
      metric_name    = "ConsoleLoginNoMFA"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    # Detects failed console login attempts. A burst of failures in a short window
    # may indicate a brute-force attack against an IAM user or root account.
    # Threshold is set to 5 failures in 5 minutes to reduce noise.
    "failed-console-logins" = {
      description    = "Multiple failed console login attempts (possible brute force)"
      filter_pattern = "{ $.eventName = \"ConsoleLogin\" && $.errorMessage = \"Failed authentication\" }"
      metric_name    = "FailedConsoleLogins"
      threshold      = 5
      period         = 300
      severity       = "HIGH"
    }

    ##############################################
    # IAM Changes
    ##############################################

    # Detects creation of new IAM users. New IAM users are rare in this org since
    # access is managed through Okta SSO and IAM roles. A new IAM user may indicate
    # an attacker establishing persistent access or a policy violation.
    "iam-user-created" = {
      description    = "New IAM user created"
      filter_pattern = "{ $.eventName = \"CreateUser\" }"
      metric_name    = "IAMUserCreated"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    # Detects creation of IAM access keys. Access keys provide programmatic access
    # to AWS and are a high-value target for attackers. Unauthorized key creation
    # is a common persistence mechanism after initial compromise.
    "access-key-creation" = {
      description    = "IAM access key created"
      filter_pattern = "{ $.eventName = \"CreateAccessKey\" }"
      metric_name    = "AccessKeyCreation"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    ##############################################
    # Trail / Logging Tampering
    ##############################################

    # Detects changes to CloudTrail configuration including stopping logging,
    # deleting trails, or modifying event selectors. These are high-confidence
    # indicators of an attacker attempting to blind the security team.
    "cloudtrail-changes" = {
      description    = "CloudTrail configuration changed (possible tampering)"
      filter_pattern = "{ $.eventName = \"StopLogging\" || $.eventName = \"DeleteTrail\" || $.eventName = \"UpdateTrail\" || $.eventName = \"PutEventSelectors\" }"
      metric_name    = "CloudTrailChanges"
      threshold      = 1
      period         = 300
      severity       = "CRITICAL"
    }

    # Detects deletion of CloudWatch log groups or metric filters. An attacker
    # may attempt to delete log groups to destroy evidence or remove metric
    # filters to disable alerting on their activity.
    "cloudwatch-log-tampering" = {
      description    = "CloudWatch log group or metric filter deleted (possible tampering)"
      filter_pattern = "{ $.eventName = \"DeleteLogGroup\" || $.eventName = \"DeleteMetricFilter\" }"
      metric_name    = "CloudWatchLogTampering"
      threshold      = 1
      period         = 300
      severity       = "CRITICAL"
    }

    # Detects changes to AWS Config recorders including stopping or deleting them.
    # Config provides continuous compliance monitoring. Disabling it removes
    # visibility into resource configuration changes across accounts.
    "config-recorder-changes" = {
      description    = "AWS Config recorder stopped or deleted"
      filter_pattern = "{ $.eventName = \"StopConfigurationRecorder\" || $.eventName = \"DeleteConfigurationRecorder\" || $.eventName = \"DeleteDeliveryChannel\" }"
      metric_name    = "ConfigRecorderChanges"
      threshold      = 1
      period         = 300
      severity       = "CRITICAL"
    }

    ##############################################
    # Network / Infrastructure
    ##############################################

    # Detects changes to EC2 security groups including new inbound/outbound rules.
    # Security group changes can expose services to the internet or allow lateral
    # movement between VPCs. The metric filter matches all SG changes — automation
    # role exclusions (gha-runners-role, terraform-deploy, aws-load-balancer-controller)
    # are handled in the Lambda to avoid the CW filter limitation where != on a
    # missing field silently drops the entire event.
    "security-group-changes" = {
      description    = "Security group rules modified"
      filter_pattern = "{ $.eventName = \"AuthorizeSecurityGroupIngress\" || $.eventName = \"AuthorizeSecurityGroupEgress\" || $.eventName = \"RevokeSecurityGroupIngress\" || $.eventName = \"RevokeSecurityGroupEgress\" || $.eventName = \"CreateSecurityGroup\" || $.eventName = \"DeleteSecurityGroup\" }"
      metric_name    = "SecurityGroupChanges"
      threshold      = 1
      period         = 300
      severity       = "MEDIUM"
    }

    # Detects changes to network ACLs which control traffic at the subnet level.
    # NACL changes can bypass security group rules and open unexpected network
    # paths. Less common than SG changes so higher signal value.
    "network-acl-changes" = {
      description    = "Network ACL modified"
      filter_pattern = "{ $.eventName = \"CreateNetworkAcl\" || $.eventName = \"CreateNetworkAclEntry\" || $.eventName = \"DeleteNetworkAcl\" || $.eventName = \"DeleteNetworkAclEntry\" || $.eventName = \"ReplaceNetworkAclEntry\" || $.eventName = \"ReplaceNetworkAclAssociation\" }"
      metric_name    = "NetworkACLChanges"
      threshold      = 1
      period         = 300
      severity       = "MEDIUM"
    }

    # Detects VPC creation, deletion, modification, and peering changes. VPC
    # changes can alter network isolation boundaries. Peering connections in
    # particular can bridge previously isolated environments.
    "vpc-changes" = {
      description    = "VPC created, deleted, or modified"
      filter_pattern = "{ $.eventName = \"CreateVpc\" || $.eventName = \"DeleteVpc\" || $.eventName = \"ModifyVpcAttribute\" || $.eventName = \"AcceptVpcPeeringConnection\" || $.eventName = \"CreateVpcPeeringConnection\" || $.eventName = \"DeleteVpcPeeringConnection\" }"
      metric_name    = "VPCChanges"
      threshold      = 1
      period         = 300
      severity       = "MEDIUM"
    }

    # Detects changes to route tables which control where network traffic flows.
    # Malicious route changes can redirect traffic through attacker-controlled
    # infrastructure or create data exfiltration paths.
    "route-table-changes" = {
      description    = "Route table modified"
      filter_pattern = "{ $.eventName = \"CreateRoute\" || $.eventName = \"CreateRouteTable\" || $.eventName = \"DeleteRoute\" || $.eventName = \"DeleteRouteTable\" || $.eventName = \"ReplaceRoute\" || $.eventName = \"ReplaceRouteTableAssociation\" }"
      metric_name    = "RouteTableChanges"
      threshold      = 1
      period         = 300
      severity       = "MEDIUM"
    }

    ##############################################
    # Data Exfil / Access
    ##############################################

    # Detects S3 bucket policy changes. Bucket policies control who can access
    # data in S3. An attacker may modify a policy to grant external access
    # for data exfiltration or to a backdoor account.
    "s3-bucket-policy-changes" = {
      description    = "S3 bucket policy modified"
      filter_pattern = "{ $.eventName = \"PutBucketPolicy\" || $.eventName = \"DeleteBucketPolicy\" }"
      metric_name    = "S3BucketPolicyChanges"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    # Detects changes to S3 public access block settings at bucket or account level.
    # Removing public access blocks can expose S3 data to the internet. This is
    # a common misconfiguration exploited in data breaches.
    "s3-public-access-changes" = {
      description    = "S3 public access block settings changed"
      filter_pattern = "{ $.eventName = \"PutBucketPublicAccessBlock\" || $.eventName = \"DeleteBucketPublicAccessBlock\" || $.eventName = \"PutAccountPublicAccessBlock\" || $.eventName = \"DeleteAccountPublicAccessBlock\" }"
      metric_name    = "S3PublicAccessChanges"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    # Detects KMS key disabling or scheduled deletion. KMS keys protect encrypted
    # data at rest. Disabling or deleting a key can render encrypted data permanently
    # inaccessible — either as sabotage or to cover tracks.
    "kms-key-changes" = {
      description    = "KMS key disabled or scheduled for deletion"
      filter_pattern = "{ $.eventName = \"DisableKey\" || $.eventName = \"ScheduleKeyDeletion\" }"
      metric_name    = "KMSKeyChanges"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    # Detects destructive or policy-changing actions on Secrets Manager secrets.
    # Deletion of secrets may indicate sabotage, and resource policy changes
    # could grant external access to sensitive credentials.
    "secrets-manager-changes" = {
      description    = "Secrets Manager secret deleted or policy changed"
      filter_pattern = "{ $.eventSource = \"secretsmanager.amazonaws.com\" && ($.eventName = \"DeleteSecret\" || $.eventName = \"PutResourcePolicy\" || $.eventName = \"CancelRotateSecret\") }"
      metric_name    = "SecretsManagerChanges"
      threshold      = 1
      period         = 300
      severity       = "HIGH"
    }

    ##############################################
    # Account Level
    ##############################################

    # Detects changes to the AWS Organization structure including account creation,
    # removal, or invitations. These are rare, high-impact events that change the
    # org boundary and should always be reviewed.
    "organizations-changes" = {
      description    = "AWS Organizations account change"
      filter_pattern = "{ $.eventSource = \"organizations.amazonaws.com\" && ($.eventName = \"CreateAccount\" || $.eventName = \"RemoveAccountFromOrganization\" || $.eventName = \"LeaveOrganization\" || $.eventName = \"InviteAccountToOrganization\") }"
      metric_name    = "OrganizationsChanges"
      threshold      = 1
      period         = 300
      severity       = "CRITICAL"
    }

    # Detects creation, deletion, attachment, or modification of Service Control
    # Policies. SCPs are the highest-level permission guardrails in the org.
    # Unauthorized SCP changes can remove security controls from all accounts.
    "scp-changes" = {
      description    = "Service Control Policy (SCP) changed"
      filter_pattern = "{ $.eventSource = \"organizations.amazonaws.com\" && ($.eventName = \"CreatePolicy\" || $.eventName = \"DeletePolicy\" || $.eventName = \"AttachPolicy\" || $.eventName = \"DetachPolicy\" || $.eventName = \"UpdatePolicy\") }"
      metric_name    = "SCPChanges"
      threshold      = 1
      period         = 300
      severity       = "CRITICAL"
    }
  }

  # Single source of truth for which alerts route through the legacy threshold-alarm
  # path. Currently just failed-console-logins (threshold = 5 in 5 min). Every other
  # alert routes via the subscription filter (per-event). Adding an alert here must
  # also remove it from the subscription filter pattern below — they are mutually
  # exclusive by design (see header comment above).
  alarm_routed_alert_keys = toset(["failed-console-logins"])

  # The 17 alerts that route through the subscription filter (per-event delivery).
  subscription_routed_alerts = {
    for k, v in local.cloudtrail_alerts : k => v
    if !contains(local.alarm_routed_alert_keys, k)
  }

  # The 1 alert (failed-console-logins) that retains its alarm.
  alarm_routed_alerts = {
    for k, v in local.cloudtrail_alerts : k => v
    if contains(local.alarm_routed_alert_keys, k)
  }

  # Two subscription filters — the combined OR of all 17 per-event patterns
  # comes out to ~2600 chars, well over the 1024-char-per-filter AWS limit.
  # Default quota is 2 subscription filters per log group, so we use both:
  #
  #   1. "network"  — the 4 MEDIUM-severity EC2/VPC/Route alert types, listed
  #      as a flat OR of their 24 eventNames. Python's classify_event re-maps
  #      each event back to its specific alert_key (security-group-changes,
  #      network-acl-changes, vpc-changes, or route-table-changes).
  #
  #   2. "general"  — the other 13 alerts. Most clauses are explicit eventName
  #      matches. Only `organizations.amazonaws.com` is left as a bare
  #      eventSource match because its 9 distinct alertable eventNames (4
  #      org-change + 5 SCP-change) would blow the 1024-char pattern budget;
  #      org management events are low per-account volume in practice, so
  #      the over-match noise is tolerable. Python's classify_event still
  #      drops over-matched events without ticketing them.
  #
  #      History: the bare-eventSource pattern was previously used for
  #      cloudtrail / config / kms / secretsmanager too. A 2026-06-25 review
  #      measured kms + secretsmanager at ~110K events/day across 3 of 8
  #      accounts via AWS/Usage data. At that volume a deploy/cron burst can
  #      blow past `reserved_concurrent_executions` and silently drop
  #      events — CW Logs → Lambda has no retry/DLQ for throttled invokes.
  #      Tightening to specific eventNames cuts that volume to near-zero
  #      because the names we actually alert on (DeleteSecret, DisableKey,
  #      StopLogging, etc.) are rare destructive ops, not the high-volume
  #      reads (GetSecretValue, Encrypt/Decrypt).
  #
  # Invariant: NEITHER pattern matches failed-console-logins
  # (`eventName = "ConsoleLogin" && errorMessage = "Failed authentication"`).
  # The console-login term explicitly requires `errorMessage NOT EXISTS`, so
  # failed logins flow ONLY through the threshold alarm path.

  # `$.userIdentity.type != "Root"` makes this filter mutually exclusive with
  # the `Root` clause in the general filter below. Without this guard, a Root
  # user performing an EC2/VPC/Route op would match BOTH filters, triggering
  # TWO Lambda invocations for the same event. Concurrent invocations would
  # race the dedup search-then-create and produce duplicate tickets + double
  # Slack notifications. By dropping Root events from the network filter, a
  # Root EC2 op is caught only by the general filter and classified as
  # `root-account-usage` (CRITICAL) — which is the correct higher-severity
  # classification anyway.
  # Safety note: `userIdentity.type` is always present on CloudTrail events
  # (it's a required field), so the `!=` comparison is safe here — there's
  # no missing-field-silently-fails blind spot.
  subscription_filter_pattern_network = format(
    "{ $.userIdentity.type != \"Root\" && (%s) }",
    join(" || ", [
      for n in [
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
        "CreateSecurityGroup", "DeleteSecurityGroup",
        "CreateNetworkAcl", "CreateNetworkAclEntry",
        "DeleteNetworkAcl", "DeleteNetworkAclEntry",
        "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation",
        "CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
        "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection",
        "DeleteVpcPeeringConnection",
        "CreateRoute", "CreateRouteTable", "DeleteRoute", "DeleteRouteTable",
        "ReplaceRoute", "ReplaceRouteTableAssociation",
      ] :
      format("$.eventName = \"%s\"", n)
    ])
  )

  subscription_filter_pattern_general = join(" ", [
    "{",
    join(" || ", [
      # Root API activity — Python re-checks invokedBy + eventType
      "$.userIdentity.type = \"Root\"",
      # Successful console logins — failed logins go to the threshold alarm path
      "$.eventName = \"ConsoleLogin\" && $.errorMessage NOT EXISTS",
      # IAM creates
      "$.eventName = \"CreateUser\"",
      "$.eventName = \"CreateAccessKey\"",
      # CloudTrail tampering — specific eventNames (tightened from eventSource)
      "$.eventName = \"StopLogging\"",
      "$.eventName = \"DeleteTrail\"",
      "$.eventName = \"UpdateTrail\"",
      "$.eventName = \"PutEventSelectors\"",
      # CloudWatch Logs tampering
      "$.eventName = \"DeleteLogGroup\"",
      "$.eventName = \"DeleteMetricFilter\"",
      # AWS Config recorder tampering — specific eventNames (tightened from eventSource)
      "$.eventName = \"StopConfigurationRecorder\"",
      "$.eventName = \"DeleteConfigurationRecorder\"",
      "$.eventName = \"DeleteDeliveryChannel\"",
      # S3 bucket policy + public access block
      "$.eventName = \"PutBucketPolicy\"",
      "$.eventName = \"DeleteBucketPolicy\"",
      "$.eventName = \"PutBucketPublicAccessBlock\"",
      "$.eventName = \"DeleteBucketPublicAccessBlock\"",
      "$.eventName = \"PutAccountPublicAccessBlock\"",
      "$.eventName = \"DeleteAccountPublicAccessBlock\"",
      # KMS destructive operations — specific eventNames (tightened from eventSource)
      "$.eventName = \"DisableKey\"",
      "$.eventName = \"ScheduleKeyDeletion\"",
      # Secrets Manager destructive operations — specific eventNames (tightened from eventSource)
      "$.eventName = \"DeleteSecret\"",
      "$.eventName = \"PutResourcePolicy\"",
      "$.eventName = \"CancelRotateSecret\"",
      # Organizations + SCP — left as eventSource match because the 9 specific
      # eventNames (4 org changes + 5 SCP changes) exceed the pattern budget;
      # per-account org-management volume is low so the over-match noise is
      # tolerable. Python classify_event filters precisely.
      "$.eventSource = \"organizations.amazonaws.com\"",
    ]),
    "}",
  ])
}


##############################
# SNS TOPIC
##############################

resource "aws_sns_topic" "cloudtrail_alerts" {
  name = "cloudtrail-security-alerts"

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

# Restrict SNS publishing to CloudWatch Alarms only
resource "aws_sns_topic_policy" "cloudtrail_alerts" {
  arn = aws_sns_topic.cloudtrail_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarmsPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.cloudtrail_alerts.arn
      },
      {
        Sid       = "AllowAccountSubscribe"
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.account_id }
        Action    = ["SNS:Subscribe", "SNS:Receive"]
        Resource  = aws_sns_topic.cloudtrail_alerts.arn
      }
    ]
  })
}

# Topic 2 — filtered email notifications. Lambda publishes here ONLY for real alerts
# (automation service accounts are filtered out). Email subscription lives here so
# emails are never sent for terraform-deploy, gha-runners-role, etc.
resource "aws_sns_topic" "cloudtrail_alerts_email" {
  name = "cloudtrail-security-alerts-email"

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cloudtrail_alerts_email.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.cloudtrail_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.alert_forwarder.arn
}

# Dead-letter queue for failed Lambda invocations — alerts that fail processing
# are retained here for 14 days so they can be investigated and replayed.
resource "aws_sqs_queue" "alert_forwarder_dlq" {
  name                      = "cloudtrail-alerts-dlq"
  message_retention_seconds = 1209600 # 14 days
  sqs_managed_sse_enabled   = true

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}


##############################
# SECRETS MANAGER
##############################

# Stores the Slack incoming webhook URL for the security-alerts channel.
# The secret container is created here; populate the value manually via the
# AWS console (or `aws secretsmanager put-secret-value`) after apply — see the
# Post-Apply Setup section in the README.
module "slack_webhook_secret" {
  source      = "./modules/secrets_manager"
  name        = "secops/cloudwatch-alerts/slack-webhook"
  description = "Slack webhook URL for CloudTrail security alerts"
  owner       = "SECOPS"
  service     = "cloudwatch-alerts"
}

# Stores Jira OAuth 2.0 client credentials for automated ticket creation.
# Create the secret here — add the values manually via the AWS console as JSON:
# {"client_id": "your-oauth-client-id", "client_secret": "your-oauth-client-secret"}
module "jira_api_secret" {
  source      = "./modules/secrets_manager"
  name        = "secops/cloudwatch-alerts/jira-credentials"
  description = "Jira API credentials for CloudTrail alert ticket creation in the SECOPS project"
  owner       = "SECOPS"
  service     = "cloudwatch-alerts"
}


##############################
# LAMBDA - ALERT FORWARDER
##############################

resource "aws_lambda_function" "alert_forwarder" {
  function_name    = "cloudtrail-alert-forwarder"
  description      = "Forwards CloudTrail subscription-filter events and the failed-console-logins threshold alarm to Slack + Jira + email"
  filename         = data.archive_file.alert_forwarder.output_path
  source_code_hash = data.archive_file.alert_forwarder.output_base64sha256
  handler          = "cloudwatch_alert_forwarder.handler"
  runtime          = "python3.12"
  # CW Logs subscription filter can batch many CloudTrail events into one
  # Lambda payload. Each event hits Jira + Slack + email; even with
  # secret/token caching, a worst-case batch can exceed 90s. 300s gives ample
  # headroom and matches the Lambda max billable runtime tier for this class.
  timeout     = 300
  memory_size = 128
  # Bumped 5 → 50 on 2026-06-25 review. CW Logs subscription filter → Lambda
  # delivery is synchronous with no retry/DLQ for throttled invokes: when
  # concurrent invocations exceed this cap, the event is dropped silently.
  # Old cap of 5 was set in the alarm-based world (~1 fire/min peak) and was
  # not safe under the new per-event delivery model. Even after tightening
  # the over-match patterns above, deploy/cron bursts can spike well past 5
  # concurrent. 50 is comfortably below the account-level Lambda concurrency
  # limit (1000) while still acting as a blast-radius cap.
  reserved_concurrent_executions = 50
  role                           = aws_iam_role.alert_forwarder.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.alert_forwarder_dlq.arn
  }

  environment {
    variables = {
      SLACK_SECRET_ARN      = module.slack_webhook_secret.secret_arn
      SLACK_ONCALL_GROUP_ID = var.slack_oncall_group_id
      JIRA_SECRET_ARN       = module.jira_api_secret.secret_arn
      JIRA_CLOUD_ID         = var.jira_cloud_id
      JIRA_BROWSE_URL       = "https://company.atlassian.net/browse"
      JIRA_PROJECT_KEY      = "SECOPS"
      JIRA_PARENT_KEY       = "SECOPS-1000"
      JIRA_ISSUE_TYPE       = "Task"
      EMAIL_SNS_TOPIC       = aws_sns_topic.cloudtrail_alerts_email.arn
    }
  }

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

resource "aws_lambda_permission" "sns_invoke" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert_forwarder.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.cloudtrail_alerts.arn
}

resource "aws_cloudwatch_log_group" "alert_forwarder" {
  name              = "/aws/lambda/cloudtrail-alert-forwarder"
  retention_in_days = 30

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

# IAM role for the Lambda function
resource "aws_iam_role" "alert_forwarder" {
  name               = "cloudtrail-alert-forwarder"
  assume_role_policy = data.aws_iam_policy_document.alert_forwarder_assume_role.json

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

resource "aws_iam_role_policy" "alert_forwarder" {
  name   = "cloudtrail-alert-forwarder"
  role   = aws_iam_role.alert_forwarder.id
  policy = data.aws_iam_policy_document.alert_forwarder_policy.json
}


##############################
# CLOUDWATCH METRIC FILTERS
##############################

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_alerts" {
  for_each = local.cloudtrail_alerts

  name           = "cloudtrail-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.filter_pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = "CloudTrailAlerts"
    value     = "1"
  }
}


##############################
# CLOUDWATCH ALARMS
##############################

# Threshold-routed alerts only — currently just failed-console-logins (5+/5min).
# The 17 other alerts moved to the subscription filter path below; their alarms
# are removed because the subscription filter delivers events to the Lambda
# directly without the indexing race that get_recent_events used to lose.
resource "aws_cloudwatch_metric_alarm" "cloudtrail_alerts" {
  for_each = local.alarm_routed_alerts

  alarm_name        = "cloudtrail-${each.key}"
  alarm_description = "[${each.value.severity}] ${each.value.description}"

  namespace           = "CloudTrailAlerts"
  metric_name         = each.value.metric_name
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = each.value.threshold
  period              = each.value.period
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions    = []

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
    "Severity"    = each.value.severity
  }
}


##############################
# SUBSCRIPTION FILTERS (per-event delivery)
##############################

# Delivers each matched CloudTrail event directly to the Lambda. Replaces the
# metric-filter→alarm→SNS→Lambda chain that used to lose enrichment events to
# filter_log_events indexing lag. Two filters because the combined OR pattern
# exceeds AWS's 1024-char-per-filter limit — see locals header above.
resource "aws_lambda_permission" "subscription_filter_invoke" {
  statement_id   = "AllowCloudWatchLogsInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.alert_forwarder.function_name
  principal      = "logs.amazonaws.com"
  source_arn     = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_alerts_network" {
  depends_on = [aws_lambda_permission.subscription_filter_invoke]

  name            = "cloudtrail-alert-forwarder-network"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  destination_arn = aws_lambda_function.alert_forwarder.arn
  filter_pattern  = local.subscription_filter_pattern_network
  distribution    = "ByLogStream"
}

resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_alerts_general" {
  depends_on = [aws_lambda_permission.subscription_filter_invoke]

  name            = "cloudtrail-alert-forwarder-general"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  destination_arn = aws_lambda_function.alert_forwarder.arn
  filter_pattern  = local.subscription_filter_pattern_general
  distribution    = "ByLogStream"
}
