##############################################
# For cloudtrail and associated resources
##############################################
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}


data "aws_iam_policy_document" "org_cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.org_cloudtrail.arn]

  }

  statement {
    sid    = "AWSCloudTrailAccountWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.org_cloudtrail.arn}/${var.s3_key_prefix}/AWSLogs/${aws_organizations_account.this["root"].id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

  }

  statement {
    sid    = "AWSCloudTrailOrganizationWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.org_cloudtrail.arn}/${var.s3_key_prefix}/AWSLogs/${aws_organizations_organization.this.id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # Allow Security account to read CloudTrail logs for Athena queries
  statement {
    sid    = "AthenaSecurityAccountGetObjects"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${aws_organizations_account.this["security"].id}:root"]
    }

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.org_cloudtrail.arn}/*"]
  }

  statement {
    sid    = "AthenaSecurityAccountListBucket"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${aws_organizations_account.this["security"].id}:root"]
    }

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [aws_s3_bucket.org_cloudtrail.arn]
  }
}



# Policy for allowing object replication - role assumption
data "aws_iam_policy_document" "replication_assume_role_policy" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
    ]
    principals {
      type = "Service"
      identifiers = [
        "s3.amazonaws.com",
      ]
    }
  }
}


# Policy for allowing object replication - replication
data "aws_iam_policy_document" "replication_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.org_cloudtrail.arn,
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
    ]
    resources = [
      "${aws_s3_bucket.org_cloudtrail.arn}/*",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
    ]
    resources = [
      "${aws_s3_bucket.org_cloudtrail_replication.arn}/*",
    ]
  }
}


##############################
# CloudTrail -> CloudWatch Logs IAM
##############################

data "aws_iam_policy_document" "cloudtrail_cloudwatch_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_policy" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}


##############################
# Alert Forwarder Lambda IAM
##############################

data "aws_iam_policy_document" "alert_forwarder_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "alert_forwarder_policy" {
  # CloudWatch Logs — write Lambda logs and read CloudTrail logs for event enrichment
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.alert_forwarder.arn}:*"]
  }

  # Secrets Manager — read Slack webhook URL and Jira API credentials
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [module.slack_webhook_secret.secret_arn, module.jira_api_secret.secret_arn]
  }

  # SQS — send failed invocations to dead-letter queue
  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alert_forwarder_dlq.arn]
  }

  # SNS — publish filtered alerts to the email topic (real alerts only)
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.cloudtrail_alerts_email.arn]
  }
}


##############################
# Lambda zip packaging
##############################

data "archive_file" "alert_forwarder" {
  type        = "zip"
  source_file = "${path.module}/files/cloudwatch_alert_forwarder.py"
  output_path = "${path.module}/files/cloudwatch_alert_forwarder.zip"
}
