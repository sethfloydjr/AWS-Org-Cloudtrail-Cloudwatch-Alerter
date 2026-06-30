#This set of resources creates a CloudTrail trail for the organization
# and enables it to log events for all accounts in the organization.
# This includes resources for S3 bucket, CloudTrail trail, and necessary IAM policies.
# For more info on Organization CloudTrail, see:
# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html

##############################
# CLOUDTRAIL
##############################

resource "aws_cloudtrail" "org_cloudtrail" {
  depends_on = [aws_s3_bucket.org_cloudtrail, aws_iam_role_policy.cloudtrail_cloudwatch]

  name                          = "company-org-cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true
  s3_bucket_name                = var.bucket_name
  s3_key_prefix                 = var.s3_key_prefix

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}


##############################
# CLOUDWATCH LOGS
##############################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/company-org-cloudtrail"
  retention_in_days = 90

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name               = "company-org-cloudtrail-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_assume_role.json

  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "company-org-cloudtrail-cloudwatch"
  role   = aws_iam_role.cloudtrail_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_policy.json
}


###############################################
# S3 Bucket
###############################################
resource "aws_s3_bucket" "org_cloudtrail" {
  bucket        = var.bucket_name
  force_destroy = false
  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

# Server access logging for the CloudTrail bucket. Enabled only when
# var.s3_access_log_bucket is set (the target bucket must already exist in the
# same region). Recommended for production — S3 access logs record who read
# the audit trail itself.
resource "aws_s3_bucket_logging" "org_cloudtrail" {
  count         = var.s3_access_log_bucket == null ? 0 : 1
  bucket        = aws_s3_bucket.org_cloudtrail.id
  target_bucket = var.s3_access_log_bucket
  target_prefix = "cloudtrail-access-logs/"
  target_object_key_format {
    partitioned_prefix {
      partition_date_source = "EventTime"
    }
  }
}

# Ownership Controls
resource "aws_s3_bucket_ownership_controls" "org_cloudtrail" {
  bucket = aws_s3_bucket.org_cloudtrail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Public Access Block
resource "aws_s3_bucket_public_access_block" "org_cloudtrail" {
  bucket                  = aws_s3_bucket.org_cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "org_cloudtrail" {
  depends_on = [aws_s3_bucket.org_cloudtrail]
  bucket     = aws_s3_bucket.org_cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Explicit server-side encryption for the audit-log bucket (matches the replica).
# SSE-S3/AES256 rather than a KMS CMK — CloudTrail writes here directly and SSE-S3
# avoids per-account KMS key-policy management for an org-wide trail.
resource "aws_s3_bucket_server_side_encryption_configuration" "org_cloudtrail" {
  bucket = aws_s3_bucket.org_cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle Configuration
resource "aws_s3_bucket_lifecycle_configuration" "org_cloudtrail" {
  bucket = aws_s3_bucket.org_cloudtrail.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }

  rule {
    id     = "storage"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}


resource "aws_s3_bucket_policy" "org_cloudtrail" {
  bucket = aws_s3_bucket.org_cloudtrail.id
  policy = data.aws_iam_policy_document.org_cloudtrail_bucket_policy.json
}


######################################################
# S3 Bucket for replication
######################################################

# Create a replica bucket to allow this to be replicated between regions
resource "aws_s3_bucket" "org_cloudtrail_replication" {
  depends_on    = [aws_s3_bucket.org_cloudtrail]
  provider      = aws.west2
  bucket        = "${aws_s3_bucket.org_cloudtrail.id}-replica"
  force_destroy = false
  tags = {
    "Owning Team" = "SECOPS"
    "Team"        = "SECOPS"
  }
}

# Server access logging for the replica bucket. Enabled only when
# var.s3_access_log_bucket_west2 is set (target bucket must already exist in
# us-west-2).
resource "aws_s3_bucket_logging" "org_cloudtrail_replication" {
  count         = var.s3_access_log_bucket_west2 == null ? 0 : 1
  provider      = aws.west2
  bucket        = aws_s3_bucket.org_cloudtrail_replication.id
  target_bucket = var.s3_access_log_bucket_west2
  target_prefix = "cloudtrail-access-logs/"
  target_object_key_format {
    partitioned_prefix {
      partition_date_source = "EventTime"
    }
  }
}

# Enforces bucket ownership and removes ACLs
resource "aws_s3_bucket_ownership_controls" "org_cloudtrail_replication" {
  provider = aws.west2
  bucket   = aws_s3_bucket.org_cloudtrail_replication.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "org_cloudtrail_replication" {
  depends_on = [aws_s3_bucket.org_cloudtrail_replication]
  provider   = aws.west2

  bucket = "${aws_s3_bucket.org_cloudtrail.id}-replica"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "org_cloudtrail_replication" {
  depends_on = [aws_s3_bucket.org_cloudtrail_replication]
  provider   = aws.west2

  bucket = "${aws_s3_bucket.org_cloudtrail.id}-replica"
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "org_cloudtrail_replication" {
  depends_on = [aws_s3_bucket.org_cloudtrail_replication]
  provider   = aws.west2

  bucket = "${aws_s3_bucket.org_cloudtrail.id}-replica"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "org_cloudtrail_replication" {
  depends_on = [aws_s3_bucket.org_cloudtrail_replication]
  provider   = aws.west2

  bucket = "${aws_s3_bucket.org_cloudtrail.id}-replica"

  rule {
    id     = "expire-deleted"
    status = "Enabled"

    filter {
      prefix = "" # Ensures the rule applies to all objects 
    }

    noncurrent_version_expiration {
      newer_noncurrent_versions = 5
      noncurrent_days           = 60
    }
  }
}


# Configure replication between the two buckets
resource "aws_s3_bucket_replication_configuration" "org_cloudtrail_replication" {
  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.org_cloudtrail_replication]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.org_cloudtrail.id

  rule {
    id = "replicate"

    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.org_cloudtrail_replication.arn
      storage_class = "STANDARD_IA"
    }
  }
}



#This role and policy control the replication...This is NOT for team or user access. 
resource "aws_iam_role" "replication" {
  depends_on         = [aws_s3_bucket.org_cloudtrail_replication]
  name               = "${var.bucket_name}-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume_role_policy.json
}

resource "aws_iam_policy" "replication" {
  depends_on = [aws_s3_bucket.org_cloudtrail_replication]
  name       = "${var.bucket_name}-replication"
  policy     = data.aws_iam_policy_document.replication_policy.json
}

resource "aws_iam_role_policy_attachment" "replication" {
  depends_on = [aws_s3_bucket.org_cloudtrail_replication]
  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}
