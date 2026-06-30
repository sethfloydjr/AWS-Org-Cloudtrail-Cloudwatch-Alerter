"""
CloudWatch Alert Forwarder Lambda — two-entry-point router.

Triggers and routing:

  1. CloudWatch Logs SUBSCRIPTION FILTER (per-event flow)
     Payload shape:    { "awslogs": { "data": "<base64-gzipped-json>" } }
     Dispatch:         handler() -> handle_subscription_event()
     Used for:         17 of 18 alert types — every alert with threshold = 1
     What it does:     Receives the matched CloudTrail event directly. No
                       filter_log_events query, so no indexing-lag race that
                       previously produced wall-of-N/A tickets. Each event
                       gets its own ticket, with fingerprint dedup
                       (hash of account|eventName|actor) folding burst-mode
                       automation into one ticket + comments.

  2. SNS from CloudWatch ALARM (threshold flow)
     Payload shape:    { "Records": [{ "Sns": { "Message": ... } }] }
     Dispatch:         handler() -> handle_threshold_alarm()
     Used for:         failed-console-logins ONLY (threshold = 5 in 5 min).
                       The "5+ in a 5-min window" aggregation IS the signal —
                       routing this through the subscription filter would lose
                       the threshold semantic.
     Invariant:        The Terraform subscription filter pattern excludes the
                       failed-console-logins pattern, so the same event is
                       never delivered down both paths.

Both paths fan out to Slack, Jira, and an email SNS topic. Jira is the system
of record (search-then-create with dedup); Slack and email are notification
channels that fire only when a new ticket is created.
"""

import base64
import gzip
import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ============================================================================
# CONFIG — env vars + constants
# ============================================================================

# Slack
SLACK_SECRET_ARN = os.environ["SLACK_SECRET_ARN"]

# Optional Slack user-group mention (e.g. an on-call @security-team handle).
# Set to a Slack subteam ID like "S0123456789" to ping that group on every
# alert; leave empty to post without an @-mention.
SLACK_ONCALL_GROUP_ID = os.environ.get("SLACK_ONCALL_GROUP_ID", "")

# Jira
JIRA_SECRET_ARN = os.environ["JIRA_SECRET_ARN"]
JIRA_CLOUD_ID = os.environ["JIRA_CLOUD_ID"]
JIRA_BROWSE_URL = os.environ.get("JIRA_BROWSE_URL", "https://company.atlassian.net/browse")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SECOPS")
JIRA_PARENT_KEY = os.environ.get("JIRA_PARENT_KEY", "SECOPS-1000")
JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")
JIRA_TOKEN_URL = "https://auth.atlassian.com/oauth/token"

# Email SNS (real alerts only — automation already filtered)
EMAIL_SNS_TOPIC = os.environ.get("EMAIL_SNS_TOPIC", "")

# Cap every outbound HTTP call so a hung upstream can't eat the full Lambda
# timeout. 15s rather than 10s because the Jira dedup search can occasionally
# exceed 10s during traffic spikes, producing "read operation timed out"
# errors and false-positive Slack notifications. Other calls (ticket create,
# comment add, Slack post) complete in well under 1s so the extra headroom is
# essentially free.
HTTP_TIMEOUT_SECONDS = 15

# Single retry with brief backoff for transient dedup-search failures.
# Jira-side timeouts have been observed in short bursts (~tens of seconds)
# that clear immediately after; one retry catches the tail of those events.
DEDUP_SEARCH_RETRY_BACKOFF_SECONDS = 2

# Severity → priority map (single source of truth, used by both ticket paths
# and the Slack priority display).
JIRA_PRIORITY_MAP = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3"}
JIRA_PRIORITY_DEFAULT = "P2"

SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_orange_circle:",
    "MEDIUM": ":large_yellow_circle:",
}

# Module-scope cache for credentials. Subscription-filter invocations can
# batch many CloudTrail events into one Lambda payload; refetching every
# secret on every event burns the Lambda budget and risks timeout. Bound by
# TTL so rotations propagate within minutes without requiring a redeploy.
SECRET_CACHE_TTL_SECONDS = 300  # 5 min — bounds staleness after rotation
_secret_cache = {}  # arn -> (value, expires_at_epoch)

# Jira OAuth access token: cached against the response's expires_in.
# Refresh slightly before expiry so a mid-call expiration doesn't 401.
JIRA_TOKEN_REFRESH_BUFFER_SECONDS = 60
_jira_access_token_cache = (None, 0.0)  # (token, expires_at_epoch)

# Global role-name exclusions — automation accounts whose CloudTrail events
# should NEVER ticket (no Slack, no Jira, no email). Patterns are regex-matched
# (re.search) against userIdentity.sessionContext.sessionIssuer.userName.
# Anchor with ^/$ when prefix or full-string matching is needed. Exclusion
# stays in Python rather than the subscription filter because the filter
# pattern syntax doesn't support regex.
GLOBAL_EXCLUDED_ROLE_PATTERNS = [
    re.compile(r"^terraform-deploy"),               # Terraform CI deploy role
    re.compile(r"^gha-runners-role"),               # GitHub Actions / Packer
    re.compile(r"^aws-load-balancer-controller"),   # EKS ALB/NLB controller
    re.compile(r"^company.*Eks-NodeInstanceRole$"),      # EKS node roles across all clusters
]


# ============================================================================
# EVENT CLASSIFICATION
# ============================================================================
# Predicates mirror the 17 subscription-routed filter patterns in
# cloudwatch-alerts.tf. The subscription filter delivers events that match
# ANY of these; classify_event() figures out WHICH one(s) and returns the
# highest-severity match for ticket attribution.
#
# Adding/changing an alert: edit the TF filter_pattern AND the matching
# predicate here in lockstep, plus the entry in ALERT_RULES below.
# (failed-console-logins is intentionally NOT here — it routes via SNS alarm.)
# ============================================================================


def _check_root_account_usage(event):
    ui = event.get("userIdentity", {})
    return (
        ui.get("type") == "Root"
        and "invokedBy" not in ui
        and event.get("eventType") != "AwsServiceEvent"
    )


def _check_console_login_no_mfa(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("additionalEventData", {}).get("MFAUsed") != "Yes"
        and event.get("responseElements", {}).get("ConsoleLogin") == "Success"
        and event.get("userIdentity", {}).get("type") == "IAMUser"
    )


def _check_iam_user_created(event):
    return event.get("eventName") == "CreateUser"


def _check_access_key_creation(event):
    return event.get("eventName") == "CreateAccessKey"


def _check_cloudtrail_changes(event):
    return event.get("eventName") in (
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    )


def _check_cloudwatch_log_tampering(event):
    return event.get("eventName") in ("DeleteLogGroup", "DeleteMetricFilter")


def _check_config_recorder_changes(event):
    return event.get("eventName") in (
        "StopConfigurationRecorder",
        "DeleteConfigurationRecorder",
        "DeleteDeliveryChannel",
    )


def _check_security_group_changes(event):
    return event.get("eventName") in (
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
        "CreateSecurityGroup", "DeleteSecurityGroup",
    )


def _check_network_acl_changes(event):
    return event.get("eventName") in (
        "CreateNetworkAcl", "CreateNetworkAclEntry",
        "DeleteNetworkAcl", "DeleteNetworkAclEntry",
        "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation",
    )


def _check_vpc_changes(event):
    return event.get("eventName") in (
        "CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
        "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection",
        "DeleteVpcPeeringConnection",
    )


def _check_route_table_changes(event):
    return event.get("eventName") in (
        "CreateRoute", "CreateRouteTable", "DeleteRoute", "DeleteRouteTable",
        "ReplaceRoute", "ReplaceRouteTableAssociation",
    )


def _check_s3_bucket_policy_changes(event):
    return event.get("eventName") in ("PutBucketPolicy", "DeleteBucketPolicy")


def _check_s3_public_access_changes(event):
    return event.get("eventName") in (
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock",
    )


def _check_kms_key_changes(event):
    return event.get("eventName") in ("DisableKey", "ScheduleKeyDeletion")


def _check_secrets_manager_changes(event):
    return (
        event.get("eventSource") == "secretsmanager.amazonaws.com"
        and event.get("eventName") in ("DeleteSecret", "PutResourcePolicy", "CancelRotateSecret")
    )


def _check_organizations_changes(event):
    return (
        event.get("eventSource") == "organizations.amazonaws.com"
        and event.get("eventName") in (
            "CreateAccount", "RemoveAccountFromOrganization",
            "LeaveOrganization", "InviteAccountToOrganization",
        )
    )


def _check_scp_changes(event):
    return (
        event.get("eventSource") == "organizations.amazonaws.com"
        and event.get("eventName") in (
            "CreatePolicy", "DeletePolicy", "AttachPolicy",
            "DetachPolicy", "UpdatePolicy",
        )
    )


# Ordered by severity (descending). When an event matches multiple rules
# (rare — e.g. a root user creating an IAM user), the first match wins.
ALERT_RULES = [
    ("root-account-usage",       "CRITICAL", "Root account API activity detected",                _check_root_account_usage),
    ("cloudtrail-changes",       "CRITICAL", "CloudTrail configuration changed",                  _check_cloudtrail_changes),
    ("cloudwatch-log-tampering", "CRITICAL", "CloudWatch log group or metric filter deleted",     _check_cloudwatch_log_tampering),
    ("config-recorder-changes",  "CRITICAL", "AWS Config recorder stopped or deleted",            _check_config_recorder_changes),
    ("organizations-changes",    "CRITICAL", "AWS Organizations account change",                  _check_organizations_changes),
    ("scp-changes",              "CRITICAL", "Service Control Policy (SCP) changed",              _check_scp_changes),
    ("console-login-no-mfa",     "HIGH",     "IAM user console login without MFA",                _check_console_login_no_mfa),
    ("iam-user-created",         "HIGH",     "New IAM user created",                              _check_iam_user_created),
    ("access-key-creation",      "HIGH",     "IAM access key created",                            _check_access_key_creation),
    ("s3-bucket-policy-changes", "HIGH",     "S3 bucket policy modified",                         _check_s3_bucket_policy_changes),
    ("s3-public-access-changes", "HIGH",     "S3 public access block settings changed",           _check_s3_public_access_changes),
    ("kms-key-changes",          "HIGH",     "KMS key disabled or scheduled for deletion",        _check_kms_key_changes),
    ("secrets-manager-changes",  "HIGH",     "Secrets Manager secret deleted or policy changed",  _check_secrets_manager_changes),
    ("security-group-changes",   "MEDIUM",   "Security group rules modified",                     _check_security_group_changes),
    ("network-acl-changes",      "MEDIUM",   "Network ACL modified",                              _check_network_acl_changes),
    ("vpc-changes",              "MEDIUM",   "VPC created, deleted, or modified",                 _check_vpc_changes),
    ("route-table-changes",      "MEDIUM",   "Route table modified",                             _check_route_table_changes),
]


def classify_event(event):
    """Return (alert_key, severity, description) for the highest-severity rule
    that matches `event`, or None if nothing matches. Subscription filter
    pattern guarantees at least one match, but defensive None-return handles
    pattern/predicate drift.
    """
    for alert_key, severity, description, predicate in ALERT_RULES:
        try:
            if predicate(event):
                return (alert_key, severity, description)
        except Exception as e:
            logger.warning(f"Classifier {alert_key} raised on event: {e}")
    return None


# ============================================================================
# SECRETS & IDENTITY
# ============================================================================


def get_secret(secret_arn):
    """Retrieve a secret from Secrets Manager with a short TTL cache.

    The cache (`_secret_cache`) is necessary because subscription-filter
    invocations can batch many CloudTrail events into one Lambda payload,
    and `_process_one_event` reads up to 2 secrets per event (Slack webhook +
    Jira credentials). Without the cache, batched bursts can blow the Lambda
    budget on Secrets Manager round-trips alone.

    Strips surrounding whitespace because pasting tokens into the Secrets
    Manager console commonly leaves a trailing newline that would silently
    break bearer/signature auth.
    """
    now = time.time()
    cached = _secret_cache.get(secret_arn)
    if cached and cached[1] > now:
        return cached[0]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    secret = response["SecretString"].strip()
    try:
        secret = json.loads(secret)
    except json.JSONDecodeError:
        pass
    _secret_cache[secret_arn] = (secret, now + SECRET_CACHE_TTL_SECONDS)
    return secret


def resolve_user_identity(user_identity):
    """Resolve a CloudTrail event's userIdentity to a single display string.

    Used everywhere we render a user — must not drift between callers.
    AssumedRole events with no top-level arn used to render as 'N/A' before
    the sessionContext.sessionIssuer.arn fallback was added.
    """
    if not user_identity:
        return "N/A"
    if user_identity.get("type") == "Root":
        return "ROOT"
    if "arn" in user_identity:
        return user_identity["arn"]
    session_arn = (
        user_identity.get("sessionContext", {})
        .get("sessionIssuer", {})
        .get("arn")
    )
    if session_arn:
        return session_arn
    if "userName" in user_identity:
        return user_identity["userName"]
    return "N/A"


def resolve_actor_name(user_identity):
    """Pick the most stable short identifier for fingerprinting.

    sessionIssuer.userName (role name) > userIdentity.userName > arn > 'unknown'.
    Role name is preferred because it's stable across session rotations of the
    same role; arn changes with each AssumedRole session.
    """
    if not user_identity:
        return "unknown"
    if user_identity.get("type") == "Root":
        return "ROOT"
    session_user = (
        user_identity.get("sessionContext", {})
        .get("sessionIssuer", {})
        .get("userName")
    )
    if session_user:
        return session_user
    if user_identity.get("userName"):
        return user_identity["userName"]
    if user_identity.get("arn"):
        return user_identity["arn"]
    return "unknown"


# ============================================================================
# FINGERPRINT & DEDUP
# ============================================================================


class DedupSearchError(Exception):
    """Raised when a dedup search call cannot determine whether an existing
    ticket exists (API error, network failure, malformed response).

    Critical because returning (None, None) from a search would otherwise be
    indistinguishable from "search succeeded, no match" — and the caller
    would fall through to create a new ticket, producing a duplicate every
    time the search fails. Forcing an exception here lets the dispatcher route
    the event into the failure status path instead.
    """


def _retry_dedup_search(search_callable, system_label, *args, **kwargs):
    """Call a dedup-search function with one retry on DedupSearchError.

    The Jira dedup search has been observed to hit our HTTP timeout for
    ~1-minute windows during traffic spikes. A single short retry covers the
    tail of those events without adding much latency on the happy path (only
    retries on error). If the second attempt also raises, the exception
    propagates to the caller, which converts it to "failed" status.
    """
    try:
        return search_callable(*args, **kwargs)
    except DedupSearchError as first_err:
        logger.warning(
            f"{system_label} dedup search retrying after transient failure: {first_err}"
        )
        time.sleep(DEDUP_SEARCH_RETRY_BACKOFF_SECONDS)
        return search_callable(*args, **kwargs)


def compute_fingerprint(account_id, event_name, actor):
    """Deterministic 16-char fingerprint for ticket dedup.

    Composition: hash(account|eventName|actor). Bursts of the same action by
    the same automation actor collapse into one ticket + comments. Different
    eventNames or different actors create distinct tickets so each is a
    distinct IOC.
    """
    raw = f"{account_id or 'unknown'}|{event_name or 'unknown'}|{actor or 'unknown'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _fingerprint_marker(fingerprint):
    """Sentinel string embedded in the ticket description for dedup search.
    HTML-comment form so it doesn't render visibly in Jira."""
    return f"<!-- cloudwatch-alert-fingerprint:{fingerprint} -->"


# ============================================================================
# JIRA
# ============================================================================


def get_jira_access_token():
    """Get a Jira access token using OAuth 2.0 client credentials flow (2LO).

    Cached in module scope until shortly before expiry. Atlassian tokens
    typically live ~1 hour; refreshing once per hour instead of once per
    event saves a full HTTP round-trip on every Lambda invocation.
    """
    global _jira_access_token_cache
    now = time.time()
    cached_token, cached_expiry = _jira_access_token_cache
    if cached_token and cached_expiry > now + JIRA_TOKEN_REFRESH_BUFFER_SECONDS:
        return cached_token

    jira_creds = get_secret(JIRA_SECRET_ARN)
    client_id = jira_creds["client_id"]
    client_secret = jira_creds["client_secret"]

    payload = json.dumps({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8")

    req = urllib.request.Request(
        JIRA_TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            result = json.loads(resp.read().decode())
            access_token = result["access_token"]
            # `expires_in` is seconds-from-now per RFC 6749. Default to 1 hour
            # if absent (Atlassian always returns it, but be defensive).
            expires_in = int(result.get("expires_in") or 3600)
            _jira_access_token_cache = (access_token, now + expires_in)
            return access_token
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        logger.error(f"Jira OAuth token error {e.code}: {body}")
        return None


def _jira_request(method, access_token, path, body=None):
    """Authenticated Jira REST call. Returns (status, parsed_body)."""
    url = f"https://api.atlassian.com/ex/jira/{JIRA_CLOUD_ID}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        body_bytes = resp.read()
        parsed = json.loads(body_bytes.decode()) if body_bytes else {}
        return resp.status, parsed


def find_existing_jira_issue(access_token, fingerprint):
    """Search Jira for an open issue containing this fingerprint.

    Uses POST /rest/api/3/search/jql. Atlassian retired the old
    GET /rest/api/2/search endpoint (it returns 410 with a migration pointer
    to /rest/api/3/search/jql). The fingerprint is a 16-char hex value embedded
    in the description as a comment marker, and JQL's `text ~` matches it as a
    single tokenized word, so we trust the search result directly without an
    extra per-issue description verification — false-positive probability on a
    random hex collision is effectively zero.

    Returns (key, url) for the first open match, or (None, None) when the
    search ran successfully but found no matching open issue. Open means
    statusCategory != Done.

    Raises DedupSearchError when the search itself could not be completed
    (HTTPError, network, etc.). Callers MUST treat this as a failure path
    and not fall through to create — silently treating it as "no match"
    spawns duplicate issues on every transient API outage.
    """
    jql = (
        f'project = "{JIRA_PROJECT_KEY}" '
        f'AND statusCategory != Done '
        f'AND text ~ "{fingerprint}"'
    )
    try:
        _, result = _jira_request(
            "POST",
            access_token,
            "/rest/api/3/search/jql",
            body={
                "jql": jql,
                "fields": ["summary"],
                "maxResults": 10,
            },
        )
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        logger.error(f"Jira dedup search error {e.code}: {body}")
        raise DedupSearchError(f"Jira dedup search HTTP {e.code}: {body}") from e
    except Exception as e:
        logger.error(f"Jira dedup search failed: {e}")
        raise DedupSearchError(f"Jira dedup search failed: {e}") from e

    issues = result.get("issues") or []
    if issues:
        key = issues[0].get("key")
        if key:
            return key, f"{JIRA_BROWSE_URL}/{key}"
    return None, None


def add_jira_comment(access_token, issue_key, body):
    """Add a comment to a Jira issue. Returns True on success."""
    try:
        status, _ = _jira_request(
            "POST",
            access_token,
            f"/rest/api/2/issue/{issue_key}/comment",
            body={"body": body},
        )
        return status in (200, 201)
    except urllib.error.HTTPError as e:
        body_resp = e.read().decode()
        logger.error(f"Jira comment error {e.code}: {body_resp}")
        return False
    except Exception as e:
        logger.error(f"Jira comment failed: {e}")
        return False


def create_jira_ticket(access_token, summary, description, severity):
    """Create a Jira ticket. Returns (key, url) or (None, None)."""
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "parent": {"key": JIRA_PARENT_KEY},
            "issuetype": {"name": JIRA_ISSUE_TYPE},
            "summary": summary,
            "description": description,
            "priority": {"name": JIRA_PRIORITY_MAP.get(severity, JIRA_PRIORITY_DEFAULT)},
        }
    }
    try:
        _, result = _jira_request("POST", access_token, "/rest/api/2/issue", body=payload)
        issue_key = result["key"]
        return issue_key, f"{JIRA_BROWSE_URL}/{issue_key}"
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        logger.error(f"Jira create error {e.code}: {body}")
        return None, None
    except Exception as e:
        logger.error(f"Jira create failed: {e}")
        return None, None


def jira_dispatch(summary, description, severity, fingerprint, comment_body):
    """Search-then-create for Jira with dedup.

    Returns (key, url, status). Status is one of:
        "created"        — new ticket created. key/url valid.
        "commented"      — found existing open ticket, comment appended OK.
                           key/url valid (existing ticket).
        "comment_failed" — found existing open ticket, comment append FAILED.
                           key/url valid; the activity was NOT recorded on the
                           ticket. Caller MUST notify so on-call sees the
                           missed event.
        "failed"         — auth, search, or create errored out. key/url None.

    Caller uses status (not the absence of a key) to decide whether to notify.
    """
    access_token = get_jira_access_token()
    if not access_token:
        return None, None, "failed"

    if fingerprint:
        try:
            existing_key, existing_url = _retry_dedup_search(
                find_existing_jira_issue, "Jira", access_token, fingerprint,
            )
        except DedupSearchError:
            # Search failed even after retry (already logged). Do NOT fall
            # through to create — that would duplicate issues on every
            # transient API outage. Caller notifies on the "failed" status.
            return None, None, "failed"
        if existing_key:
            commented = add_jira_comment(access_token, existing_key, comment_body)
            if commented:
                logger.info(f"Jira: dedup comment added to {existing_key}")
                return existing_key, existing_url, "commented"
            logger.error(
                f"Jira: dedup comment FAILED on existing {existing_key} — "
                "activity not recorded on the ticket; notification will fire."
            )
            return existing_key, existing_url, "comment_failed"

    key, url = create_jira_ticket(access_token, summary, description, severity)
    if key:
        return key, url, "created"
    return None, None, "failed"


# ============================================================================
# SLACK & EMAIL
# ============================================================================


def _oncall_mention():
    """Slack @-mention suffix for the on-call group, or empty if unconfigured."""
    return f" <!subteam^{SLACK_ONCALL_GROUP_ID}>" if SLACK_ONCALL_GROUP_ID else ""


def post_to_slack(message):
    """Post a message to Slack via webhook. Returns True on 200."""
    slack_secret = get_secret(SLACK_SECRET_ARN)
    if isinstance(slack_secret, str):
        webhook_url = slack_secret
    elif isinstance(slack_secret, dict):
        webhook_url = slack_secret.get("webhook_url") or slack_secret.get("url")
    else:
        logger.error("Invalid Slack secret format — expected string or dict")
        return False
    if not webhook_url:
        logger.error("Slack webhook URL is empty or missing from secret")
        return False

    payload = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        logger.error(f"Slack webhook error {e.code}: {e.read().decode()}")
        return False


def send_email_via_sns(subject, body):
    """Publish to the email SNS topic. Caller decides when (only first-create)."""
    if not EMAIL_SNS_TOPIC:
        return
    try:
        sns = boto3.client("sns")
        sns.publish(
            TopicArn=EMAIL_SNS_TOPIC,
            Subject=subject[:100],  # SNS subject hard cap
            Message=body,
        )
    except Exception as e:
        logger.error(f"Failed to publish email notification: {e}", exc_info=True)


def _slack_priority_display(severity):
    p = JIRA_PRIORITY_MAP.get(severity, JIRA_PRIORITY_DEFAULT)
    return f"{p} :alert:" if p == "P1" else p


def _slack_ticket_line(jira_key, jira_url, jira_status):
    """Render the Jira ticket line for Slack based on dispatch status."""
    if jira_status in ("created", "commented") and jira_key and jira_url:
        return f"*Jira:*\n<{jira_url}|{jira_key}>"
    if jira_status == "comment_failed" and jira_key and jira_url:
        return (
            f"*Jira:*\n<{jira_url}|{jira_key}> — comment append FAILED on existing "
            f"ticket (check Lambda logs)"
        )
    if jira_status == "failed":
        return "*Jira:*\nFailed to create ticket — check Lambda logs"
    # Defensive fallback for an unrecognized status — surface it instead of
    # silently dropping the line.
    return f"*Jira:*\nUnknown dispatch status: {jira_status!r} (check Lambda logs)"


# ============================================================================
# SUBSCRIPTION FILTER PATH (per-event tickets with dedup)
# ============================================================================


def _decode_subscription_payload(event):
    """Decode CloudWatch Logs subscription invocation: base64 → gzip → JSON.

    Shape (after decode):
      { "messageType": "DATA_MESSAGE",
        "owner": "<account-id>",
        "logGroup": "...", "logStream": "...",
        "subscriptionFilters": [...],
        "logEvents": [ { "id": ..., "timestamp": ..., "message": "<CT-event-json>" }, ... ] }
    """
    blob = event.get("awslogs", {}).get("data", "")
    if not blob:
        return None
    decoded = base64.b64decode(blob)
    raw = gzip.decompress(decoded)
    return json.loads(raw)


def _excluded_by_role(user_identity):
    """Return the matched role name if the role is excluded, else None."""
    role = (
        user_identity.get("sessionContext", {})
        .get("sessionIssuer", {})
        .get("userName", "")
    )
    if not role:
        return None
    for pattern in GLOBAL_EXCLUDED_ROLE_PATTERNS:
        if pattern.search(role):
            return role
    return None


def _format_event_for_ticket(event, severity, alert_key, description, fingerprint):
    """Build the ticket description body for a single CloudTrail event."""
    user_arn = resolve_user_identity(event.get("userIdentity", {}))
    return (
        f"Severity: {severity}\n"
        f"Alert Type: {alert_key}\n"
        f"Description: {description}\n\n"
        f"Account ID: {event.get('recipientAccountId', 'N/A')}\n"
        f"Region: {event.get('awsRegion', 'N/A')}\n"
        f"Event Time: {event.get('eventTime', 'N/A')}\n"
        f"Event Name: {event.get('eventName', 'N/A')}\n"
        f"Event Source: {event.get('eventSource', 'N/A')}\n"
        f"Source IP: {event.get('sourceIPAddress', 'N/A')}\n"
        f"User: {user_arn}\n"
        f"User Agent: {event.get('userAgent', 'N/A')}\n\n"
        f"--- Request Parameters ---\n"
        f"{json.dumps(event.get('requestParameters') or {}, indent=2, default=str)}\n\n"
        f"{_fingerprint_marker(fingerprint)}"
    )


def _format_event_for_comment(event):
    """Compact event detail block for a dedup comment on an existing ticket."""
    user_arn = resolve_user_identity(event.get("userIdentity", {}))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"Re-detected by CloudWatch alert forwarder at {now}.\n\n"
        f"Event Time: {event.get('eventTime', 'N/A')}\n"
        f"Event Name: {event.get('eventName', 'N/A')}\n"
        f"Account ID: {event.get('recipientAccountId', 'N/A')}\n"
        f"Region: {event.get('awsRegion', 'N/A')}\n"
        f"Source IP: {event.get('sourceIPAddress', 'N/A')}\n"
        f"User: {user_arn}\n"
    )


def _format_slack_message(event, severity, description, jira_key, jira_url, jira_status):
    """Slack message for a per-event ticket. Same skeleton as the threshold path
    but populated directly from the matched event."""
    emoji = SEVERITY_EMOJI.get(severity, ":warning:")
    user_name = resolve_user_identity(event.get("userIdentity", {}))
    return (
        f"*CloudTrail Alert: {description}* {emoji} {severity} security event detected{_oncall_mention()}\n\n"
        f"*Priority:*\n{_slack_priority_display(severity)}\n\n"
        f"*Provider-Service:*\nAWS - {event.get('eventSource', 'N/A')}\n\n"
        f"*Account ID:*\n{event.get('recipientAccountId', 'N/A')}\n\n"
        f"*Action:*\n{event.get('eventName', 'N/A')}\n\n"
        f"*Event Timestamp:*\n{event.get('eventTime', 'N/A')}\n\n"
        f"*Source IP:*\n{event.get('sourceIPAddress', 'N/A')}\n\n"
        f"*User:*\n{user_name}\n\n"
        f"{_slack_ticket_line(jira_key, jira_url, jira_status)}"
    )


def _format_email_body(event, severity, description, jira_url, jira_status):
    user_name = resolve_user_identity(event.get("userIdentity", {}))
    if jira_url and jira_status in ("created", "commented"):
        ticket_line = f"Jira:   {jira_url}\n"
    elif jira_url and jira_status == "comment_failed":
        ticket_line = f"Jira:   {jira_url} — comment append FAILED on existing ticket (check Lambda logs)\n"
    else:
        ticket_line = "Jira:   Failed to create ticket — check Lambda logs\n"
    return (
        f"Severity: {severity}\n"
        f"Description: {description}\n\n"
        f"Account ID: {event.get('recipientAccountId', 'N/A')}\n"
        f"Action: {event.get('eventName', 'N/A')}\n"
        f"Event Timestamp: {event.get('eventTime', 'N/A')}\n"
        f"Source IP: {event.get('sourceIPAddress', 'N/A')}\n"
        f"User: {user_name}\n\n"
        f"{ticket_line}"
    )


def _jira_state_class(status, has_key):
    """Classify a Jira dispatch outcome for cross-event transition checks.

    Buckets:
      "ok"     — ticket exists AND activity (create or comment) was recorded
                 (status in {created, commented} AND a ticket key is set)
      "broken" — either no ticket, OR a ticket exists but the comment append
                 failed (status in {failed, comment_failed}). Activity for this
                 event WAS NOT recorded.

    Used by the same-batch retry path to detect notification-worthy state
    transitions. A change between classes (in either direction) means on-call
    should see this event; same-class to same-class means the initial
    notification already covered it.
    """
    if has_key and status in ("created", "commented"):
        return "ok"
    return "broken"


def _process_one_event(event, seen_fingerprints=None):
    """Per-event flow: exclude → classify → dedup-search → comment-or-create.

    `seen_fingerprints` is an invocation-scoped dict tracking which ticket the
    first event in this batch produced per fingerprint. Same-batch bursts with
    identical (account, eventName, actor) take the follow-up path: they don't
    re-dispatch (would race the dedup search-then-create and create
    duplicates) but they DO append the new event's details as a comment to the
    first event's ticket. Net result: a burst collapses into ONE Slack/email
    notification + a running comment trail on the ticket, matching the
    documented dedup story.
    """
    if seen_fingerprints is None:
        seen_fingerprints = {}

    user_identity = event.get("userIdentity", {})

    # Role exclusion runs first so excluded automation never enters the
    # ticket/Slack/email path. Logged at INFO with the matched role so we
    # can audit suppression after the fact.
    matched_role = _excluded_by_role(user_identity)
    if matched_role:
        logger.info(
            f"Suppressed event from excluded role '{matched_role}' "
            f"(eventName={event.get('eventName')}, "
            f"account={event.get('recipientAccountId')})"
        )
        return

    classification = classify_event(event)
    if not classification:
        # The subscription filter intentionally over-matches some low-volume
        # eventSources (cloudtrail/config/kms/secretsmanager/organizations) to
        # fit within the 1024-char-per-filter limit. Events from those sources
        # that don't match a specific Python predicate land here and get
        # dropped silently. Logged at DEBUG so the routine over-match traffic
        # doesn't fill CloudWatch Logs.
        logger.debug(
            "Event over-matched by subscription filter but did not match any "
            f"alert predicate. eventName={event.get('eventName')}, "
            f"source={event.get('eventSource')}"
        )
        return
    alert_key, severity, description = classification

    account_id = event.get("recipientAccountId", "unknown")
    event_name = event.get("eventName", "unknown")
    actor = resolve_actor_name(user_identity)
    if actor == "unknown":
        logger.warning(f"Could not resolve actor name for event eventName={event_name}")

    fingerprint = compute_fingerprint(account_id, event_name, actor)

    # Same-invocation dedup. Decision tree on cache state:
    #
    #   1. No cache entry (first event for this fingerprint in the batch)
    #      → dispatch normally, populate cache.
    #
    #   2. Cache entry, Jira is in state "ok"
    #      → follow-up path: append a comment to the cached ticket.
    #      Don't re-dispatch (would race dedup search-then-create). The comment
    #      result is synthesized into jira_status and the SAME notify gate
    #      below evaluates the state transition — a comment failure becomes
    #      "comment_failed" and surfaces to Slack/email via the ok→broken
    #      transition, matching the dispatch path's `comment_failed` behavior.
    #
    #   3. Cache entry, Jira is in state "broken" — i.e. failed, OR
    #      comment_failed (ticket exists but the comment didn't land)
    #      → fall through and re-dispatch. If the API was transient and has
    #      recovered between event 1 and now, this event lands a ticket and
    #      the dedup search adds its comment too.
    #
    # All paths converge on the same notify gate below, which gates on
    # state-class TRANSITION when prior_dispatch is set (so repeat-state stays
    # silent — event 1 already notified — but any change in either direction
    # surfaces).
    prior_dispatch = seen_fingerprints.get(fingerprint)
    is_comment_only_followup = False
    if prior_dispatch is not None:
        # Use _jira_state_class so this gate and the notify gate below share
        # one definition of "needs attention". Critically: this includes
        # comment_failed (ticket present, comment didn't land) in the retry
        # set; without that, a comment_failed → comment_failed repeat would
        # silently drop event N's activity from the trail.
        jira_broken = _jira_state_class(
            prior_dispatch.get("jira_status", "failed"),
            prior_dispatch.get("jira_key") is not None,
        ) == "broken"
        is_comment_only_followup = not jira_broken
        if is_comment_only_followup:
            logger.info(
                f"Same-invocation dedup — appending follow-up comment for fingerprint "
                f"already dispatched in this batch. eventName={event_name}, "
                f"actor={actor}, fingerprint={fingerprint}"
            )
        else:
            logger.info(
                f"Same-invocation dedup — re-dispatching to retry broken Jira state. "
                f"Notification fires only on state-class transition. "
                f"eventName={event_name}, actor={actor}, fingerprint={fingerprint}"
            )

    # Default outputs the notify gate consumes. Either branch below populates them.
    jira_key, jira_url, jira_status = None, None, "failed"

    if is_comment_only_followup:
        # Comment-only follow-up: synthesize "current state" from the cached
        # ticket info + comment result. Feeds the SAME notify gate as the
        # dispatch path so comment failures surface uniformly.
        jira_key = prior_dispatch.get("jira_key")
        jira_url = prior_dispatch.get("jira_url")
        commented = False
        try:
            access_token = get_jira_access_token()  # cached at module scope
            commented = bool(
                access_token
                and add_jira_comment(access_token, jira_key, _format_event_for_comment(event))
            )
        except Exception as e:
            logger.error(
                f"Same-batch follow-up Jira comment errored: {e} "
                f"(eventName={event_name}, fingerprint={fingerprint})"
            )
        if commented:
            logger.info(
                f"Same-batch follow-up: Jira comment appended to {jira_key} "
                f"(eventName={event_name}, fingerprint={fingerprint})"
            )
            jira_status = "commented"
        else:
            logger.error(
                f"Same-batch follow-up: Jira comment FAILED on {jira_key} "
                f"(eventName={event_name}, fingerprint={fingerprint})"
            )
            jira_status = "comment_failed"
    else:
        # Dispatch path (first event for this fingerprint, OR retry of a
        # broken-on-event-1 fingerprint). Reserve the slot before dispatch so
        # follow-up logic sees we're in progress.
        seen_fingerprints[fingerprint] = {}

        summary = f"Cloudwatch Alert - {account_id} - {event_name} by {actor}"
        if len(summary) > 255:
            summary = summary[:252] + "..."

        ticket_description = _format_event_for_ticket(event, severity, alert_key, description, fingerprint)
        comment_body = _format_event_for_comment(event)

        try:
            jira_key, jira_url, jira_status = jira_dispatch(
                summary, ticket_description, severity, fingerprint, comment_body,
            )
        except Exception as e:
            logger.error(f"Jira dispatch failed for {event_name}: {e}", exc_info=True)

    # Populate same-batch cache with ticket info AND status so subsequent
    # events with this fingerprint can determine whether to comment, retry a
    # failed dispatch, or skip. Only cache the key/URL from statuses that
    # successfully identified a ticket (created / commented / comment_failed —
    # the last because the ticket exists even though our comment didn't land;
    # the next event can retry). Status is cached unconditionally so
    # retry-eligibility can be computed.
    _ticket_bearing_statuses = ("created", "commented", "comment_failed")
    seen_fingerprints[fingerprint] = {
        "jira_key": jira_key if jira_status in _ticket_bearing_statuses else None,
        "jira_url": jira_url if jira_status in _ticket_bearing_statuses else None,
        "jira_status": jira_status,
    }

    # Notification decision rule:
    #   Silent only when Jira cleanly "commented" on an existing open ticket.
    #
    # Any "created" must notify (new ticket = on-call should see it).
    # Any "failed" or "comment_failed" must notify (the event activity wasn't
    #   recorded — on-call needs to know an alert was received but didn't fully
    #   process; comment_failed in particular leaves the existing ticket stale,
    #   with this occurrence's details missing from its history).
    silent_dedup = jira_status == "commented"
    failure_present = jira_status in ("failed", "comment_failed")
    notify = not silent_dedup

    # Override for same-batch retry case: event 1 already notified the initial
    # state of this fingerprint. We re-notify only on a STATE-CLASS TRANSITION,
    # in either direction:
    #   - broken → ok  (recovery — the ticket finally landed)
    #   - ok → broken  (new failure — a previously-OK system's comment didn't
    #                   land on this retry, so this event's activity is missing
    #                   from the ticket trail and on-call needs to know)
    # Same-class → same-class is silent (event 1 already covered that state).
    if prior_dispatch is not None:
        prior_class = _jira_state_class(
            prior_dispatch.get("jira_status", "failed"),
            prior_dispatch.get("jira_key") is not None,
        )
        current_class = _jira_state_class(jira_status, jira_key is not None)
        notify = prior_class != current_class
        if notify:
            logger.info(
                f"Same-batch transition — state class changed; notifying. "
                f"jira: {prior_class}→{current_class}, "
                f"jira={jira_key} ({jira_status}), fingerprint={fingerprint}"
            )
        else:
            logger.info(
                f"Same-batch retry produced no state transition; staying silent "
                f"(initial notification already fired for this fingerprint). "
                f"jira: {prior_class}={current_class}, "
                f"jira={jira_key} ({jira_status}), fingerprint={fingerprint}"
            )

    if silent_dedup:
        logger.info(
            f"Dedup hit — matched existing ticket and commented OK, no new "
            f"notification. eventName={event_name}, jira={jira_key} "
            f"({jira_status}), fingerprint={fingerprint}"
        )
    elif failure_present and prior_dispatch is None:
        # Only ERROR-log for FIRST events with failures. Same-batch retry
        # events log their own decision context in the prior_dispatch block
        # above; re-logging at ERROR here would double-log and misleadingly
        # suggest a fresh failure.
        logger.error(
            f"Ticket dispatch incomplete — Slack/email will fire so on-call sees the alert. "
            f"eventName={event_name}, jira={jira_key} ({jira_status}), "
            f"fingerprint={fingerprint}"
        )

    if notify:
        try:
            post_to_slack(_format_slack_message(
                event, severity, description, jira_key, jira_url, jira_status,
            ))
        except Exception as e:
            logger.error(f"Slack notification failed for {event_name}: {e}", exc_info=True)

        try:
            send_email_via_sns(
                f"CloudTrail Alert: {description} [{severity}]",
                _format_email_body(event, severity, description, jira_url, jira_status),
            )
        except Exception as e:
            logger.error(f"Email notification failed for {event_name}: {e}", exc_info=True)

    logger.info(
        f"Processed event: alert_key={alert_key}, event_name={event_name}, "
        f"actor={actor}, account={account_id}, jira={jira_key} ({jira_status})"
    )


def handle_subscription_event(event):
    """Subscription filter invocation: decode payload, process each logEvent."""
    payload = _decode_subscription_payload(event)
    if not payload:
        logger.error("Subscription payload missing awslogs.data")
        return {"statusCode": 400}

    log_events = payload.get("logEvents", []) or []
    logger.info(
        f"Subscription invocation: messageType={payload.get('messageType')}, "
        f"owner={payload.get('owner')}, logEvents={len(log_events)}"
    )

    # Invocation-scoped fingerprint cache — see _process_one_event docstring.
    # Maps fingerprint → {"jira_key": ..., "jira_url": ..., "jira_status": ...}
    # so subsequent same-fingerprint events in this batch can append comments
    # to the first event's ticket. Lives only for the duration of this Lambda
    # invocation; cross-invocation dedup is the Jira search-then-create flow.
    seen_fingerprints = {}

    for log_event in log_events:
        try:
            cloudtrail_event = json.loads(log_event["message"])
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse logEvent message: {e}")
            continue
        try:
            _process_one_event(cloudtrail_event, seen_fingerprints)
        except Exception as e:
            logger.error(f"Per-event processing failed: {e}", exc_info=True)

    return {"statusCode": 200}


# ============================================================================
# THRESHOLD ALARM PATH (failed-console-logins only)
# ============================================================================


def handle_threshold_alarm(event):
    """SNS-from-CloudWatch-Alarm invocation: failed-console-logins (5+/5min).

    No per-event enrichment query — the threshold IS the signal. One ticket
    per alarm fire (no fingerprint dedup; the 5-min window already aggregates).

    Role-exclusion suppression (GLOBAL_EXCLUDED_ROLE_PATTERNS) is intentionally
    NOT applied here. Two independent reasons:

      1. Field shape. Failed-ConsoleLogin events don't carry
         `userIdentity.sessionContext.sessionIssuer.userName` — that field
         only populates on AssumedRole calls, and a failed console login
         never reaches the session-creation step. The exclusion patterns are
         all matched against that field, so they'd produce zero matches
         against this alert's events regardless of role.

      2. Pattern shape. All current exclusion patterns are *role* names
         (terraform-deploy, gha-runners-role, aws-load-balancer-controller,
         company.*Eks-NodeInstanceRole). None match human IAM-user names or
         SAML-federated user identifiers, which is what's actually present
         on failed-console-login events.

    If the exclusion ever needs to apply to failed logins (e.g. blanket-
    suppress all logins from a known misconfigured IAM user), add a
    userIdentity.userName-based check here explicitly rather than relying on
    the role-pattern set.
    """
    for record in event.get("Records", []):
        try:
            sns_message = json.loads(record["Sns"]["Message"])
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse SNS message: {e}")
            continue

        alarm_name = sns_message.get("AlarmName", "Unknown")
        alarm_desc = sns_message.get("AlarmDescription", "")
        new_state = sns_message.get("NewStateValue", "ALARM")
        state_reason = sns_message.get("NewStateReason", "")
        state_change_time = sns_message.get(
            "StateChangeTime",
            datetime.now(timezone.utc).isoformat(),
        )

        if new_state != "ALARM":
            logger.info(f"Skipping {alarm_name} — state is {new_state}")
            continue

        # Severity is embedded in alarm description as a [SEVERITY] prefix.
        severity = "HIGH"
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if f"[{sev}]" in (alarm_desc or ""):
                severity = sev
                break
        display_desc = alarm_desc
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            display_desc = display_desc.replace(f"[{sev}] ", "")

        emoji = SEVERITY_EMOJI.get(severity, ":warning:")

        summary = f"Cloudwatch Alert - {display_desc}"
        if len(summary) > 255:
            summary = summary[:252] + "..."

        ticket_description = (
            f"Severity: {severity}\n"
            f"Alarm: {alarm_name}\n"
            f"Description: {display_desc}\n"
            f"State Change Time: {state_change_time}\n"
            f"State Reason: {state_reason}\n\n"
            f"This alarm fires when the threshold is met (5+ failed console "
            f"logins in 5 minutes). Investigate via Athena / CloudTrail "
            f"console for the specific failed-login events."
        )

        # No fingerprint — alarm window already aggregates. Each alarm fire
        # gets its own fresh ticket. Status values mirror the subscription
        # path's vocabulary so the Slack/email formatters render uniformly:
        #   "created"  — new ticket exists
        #   "failed"   — attempted but errored
        jira_key, jira_url, jira_status = None, None, "failed"
        try:
            access_token = get_jira_access_token()
            if access_token:
                jira_key, jira_url = create_jira_ticket(
                    access_token, summary, ticket_description, severity,
                )
                jira_status = "created" if jira_key else "failed"
        except Exception as e:
            logger.error(f"Jira ticket creation failed for {alarm_name}: {e}", exc_info=True)
            jira_status = "failed"

        try:
            slack_message = (
                f"*CloudTrail Alert: {display_desc}* {emoji} {severity} security event detected{_oncall_mention()}\n\n"
                f"*Priority:*\n{_slack_priority_display(severity)}\n\n"
                f"*Alarm:*\n{alarm_name}\n\n"
                f"*State Change Time:*\n{state_change_time}\n\n"
                f"*State Reason:*\n{state_reason}\n\n"
                f"{_slack_ticket_line(jira_key, jira_url, jira_status)}"
            )
            post_to_slack(slack_message)
        except Exception as e:
            logger.error(f"Slack notification failed for {alarm_name}: {e}", exc_info=True)

        try:
            if jira_url and jira_status == "created":
                ticket_line = f"Jira:   {jira_url}\n"
            else:
                ticket_line = "Jira:   Failed to create ticket — check Lambda logs\n"
            email_body = (
                f"Severity: {severity}\n"
                f"Alarm: {alarm_name}\n"
                f"Description: {display_desc}\n"
                f"State Change Time: {state_change_time}\n"
                f"State Reason: {state_reason}\n\n"
                f"{ticket_line}"
            )
            send_email_via_sns(
                f"CloudTrail Alert: {display_desc} [{severity}]",
                email_body,
            )
        except Exception as e:
            logger.error(f"Email notification failed for {alarm_name}: {e}", exc_info=True)

        logger.info(
            f"Processed alarm: {alarm_name}, severity={severity}, "
            f"jira={jira_key} ({jira_status})"
        )

    return {"statusCode": 200}


# ============================================================================
# HANDLER ROUTER
# ============================================================================


def handler(event, context):
    """Dispatch by payload shape.

    Subscription filter (CloudWatch Logs):  { "awslogs": { "data": "<base64>" } }
    Threshold alarm (SNS from CloudWatch):  { "Records": [{ "Sns": {...} }] }
    """
    if "awslogs" in event:
        return handle_subscription_event(event)
    if event.get("Records"):
        return handle_threshold_alarm(event)
    logger.error(f"Unknown event shape — keys: {sorted(event.keys())}")
    return {"statusCode": 400}
