# Design notes

A deeper companion to the [README](README.md) — the things you only learn by
reading every file. The README is the operational guide; this is the
"why it's shaped this way" doc for anyone (human or agent) picking up the code.

---

## Why three concerns share one state file

Organizations management, the org CloudTrail, and the alert pipeline all live
together because they all run in the **org-management (root) account** and all
depend on org-level data. The trail delivers CloudWatch Logs *locally* to the
root account, so the metric filters, alarms, and Lambda must live there too —
they can't be pushed to a separate security account. There is no per-account
fan-out here; the org trail centralizes everything to one log group on purpose.

Files map cleanly to the concerns:

- `accounts.tf`, `organization.tf`, `_outputs.tf` → org membership and outputs
- `cloudtrail.tf` → trail + S3 + CloudWatch Logs role
- `cloudwatch-alerts.tf` → metric/subscription filters, the one alarm, SNS, Lambda, secrets, IAM
- `files/cloudwatch_alert_forwarder.py` → the Lambda logic
- `_data.tf` → every `aws_iam_policy_document` (IAM lives here, not in resource files)

---

## How the alert Lambda works

`files/cloudwatch_alert_forwarder.py` has **two entry points**, routed by
payload shape in `handler()`:

```text
handler(event)
  ├─ event["awslogs"]        → handle_subscription_event(event)   # per-event, 17 alerts
  └─ event["Records"][].Sns  → handle_threshold_alarm(event)      # failed-console-logins only
```

### Subscription event flow (per-event, no enrichment race)

1. **Decode** — `awslogs.data` is base64 → gzip → JSON wrapping `logEvents[]`,
   each `.message` a CloudTrail event.
2. **Exclude automation** — match `sessionContext.sessionIssuer.userName` against
   `GLOBAL_EXCLUDED_ROLE_PATTERNS`; on match, drop with an INFO log.
3. **Classify** — `classify_event()` walks `ALERT_RULES` (CRITICAL → HIGH →
   MEDIUM) and returns the highest-severity match. The subscription pattern
   intentionally over-matches some low-volume sources; events that match no
   predicate are dropped silently at DEBUG.
4. **Fingerprint** — `sha256(account | eventName | actor)[:16]`, where actor is
   `sessionIssuer.userName` (preferred, stable across session rotations),
   falling back to `userName` → `arn` → `"unknown"`.
5. **Dedup search** — search Jira for an OPEN issue (`statusCategory != Done`)
   whose description contains the fingerprint marker.
6. **Comment-or-create** — match found → append a comment; no match → create a
   ticket with the fingerprint marker embedded.
7. **Notify only on create** — Slack + email fire only when a new ticket is
   created. A comment-only dedup hit is silent; the comment trail is the record.

### Threshold alarm flow (failed-console-logins only)

The alarm already aggregated 5+ failures in 5 minutes — *that* is the signal, so
there's no enrichment query and no fingerprint dedup. Each fire gets its own
ticket plus Slack + email.

Role-exclusion is intentionally **not** applied here: failed-ConsoleLogin events
carry no `sessionIssuer.userName` (no session was created), and the patterns are
all role names, not the IAM-user / SAML identifiers present on a failed login.
See the `handle_threshold_alarm` docstring for the full rationale.

---

## Dedup semantics (the subtle part)

Dedup is **state-based, not time-based**. A ticket absorbs matching activity as
comments until a human closes it; the next matching event *after* a close opens
a fresh ticket and re-notifies. There is no clock — closing the ticket is the
"incident resolved" signal. **Operational implication:** triage and close, or
stale open tickets silently absorb activity that should have re-alerted.

Two layers of dedup:

- **Cross-invocation** — the Jira search-then-create flow above.
- **Same-invocation** — one subscription batch can contain many events with the
  same fingerprint. An invocation-scoped cache (`seen_fingerprints`) means the
  first event dispatches and notifies; subsequent same-fingerprint events append
  a comment to that ticket rather than racing the search-then-create.

The same-invocation path shares one definition of "needs attention" with the
notify gate (`_jira_state_class`: `ok` vs `broken`). A burst that all commits
cleanly notifies once; if a later event's comment *fails* (ticket exists but the
activity wasn't recorded), that's an `ok → broken` transition and it re-notifies
so on-call sees the gap. A dedup-search failure deliberately raises
(`DedupSearchError`) rather than returning "no match", because falling through to
create would spawn a duplicate on every transient API blip.

---

## Conventions & quirks worth knowing

- **All IAM policy documents live in `_data.tf`.** Repo convention — `data`
  blocks don't go in resource files.
- **CloudTrail bucket `force_destroy` must stay `false`.** It holds the org's
  audit trail.
- **Accounts are a `for_each` map, not copy-pasted blocks.** Add/remove members
  by editing `var.org_accounts`. The org-level wiring (FullAWSAccess SCP, IPAM /
  Config / Macie delegated admins) references `root`, `security`, and
  `interconnect` by key, so a validation enforces their presence — you get a
  clear error instead of an "Invalid index".
- **Secrets are created empty.** The `secrets_manager` module makes the secret
  container; values are populated out-of-band so credentials never enter state.
- **`get_secret()` strips whitespace** before returning — a trailing newline
  pasted into the Secrets Manager console silently breaks bearer auth.
- **Email goes through a second SNS topic.** `EMAIL_SNS_TOPIC` is published to
  *by the Lambda* (real alerts only), not subscribed to by it. The CloudWatch
  alarm publishes only to `cloudtrail_alerts`, which only the Lambda subscribes to.
- **The Jira parent epic rolls over yearly.** `JIRA_PARENT_KEY` points at the
  current year's epic; create a new one at year-end and update the env var.

---

## Cross-account note

The **security account** has cross-account read on the CloudTrail S3 bucket via
the `AthenaSecurityAccount*` statements in `_data.tf` — that's how an Athena
workgroup in a separate account queries the trail for long-range investigation.
Metric filters and alarms can't live there; the trail delivers CloudWatch Logs
to the root account, so near-real-time alerting must too.

---

## Evolution (how it got here)

The design is the result of a few deliberate migrations, each worth knowing
because the failure mode that drove it can come back if the code is "simplified":

- **Alarm-based enrichment → subscription-filter delivery.** The original path
  was 18 alarms; the Lambda received an alarm and queried `filter_log_events` to
  enrich it. That query lost a race with CloudWatch Logs ingestion lag on the
  org-aggregated group, producing wall-of-N/A tickets. Replaced with
  subscription filters that deliver the event in the payload. 17 alarms removed;
  `failed-console-logins` kept (its 5-in-5 aggregation can't be a per-event
  filter). *Don't* restore `get_recent_events` / `filter_log_events` /
  `LOOKBACK_MINUTES`.
- **Per-event fingerprint dedup added** alongside that flip, because per-event
  delivery means a 12-rule security-group edit would otherwise file 12 tickets.
- **Concurrency cap 5 → 50.** The old cap was set for the ~1-fire/min alarm era;
  per-event delivery has a burstier shape, and CW-Logs→Lambda has no retry/DLQ
  for throttled invokes, so a too-low cap silently drops events. 50 stays well
  under the 1000 account limit while bounding blast radius.
- **Jira search pinned to v3.** Atlassian retired `GET /rest/api/2/search`
  (now 410); the dedup search uses `POST /rest/api/3/search/jql`. A vendor
  endpoint retirement is exactly the kind of thing that silently breaks dedup.

---

## What not to do

- Don't add `force_destroy = true` to either CloudTrail bucket.
- Don't put `variable` / `data` / `output` blocks in resource files.
- Don't add a time window to dedup — closing the ticket is the resolved signal.
- Don't add `failed-console-logins` (or any threshold alert) to the subscription
  filter pattern — the two paths are mutually exclusive by design; double
  delivery would pair-ticket every fire.
- Don't use `!=` on a nested CloudTrail field in a metric filter; a missing field
  makes it silently match nothing and creates a blind spot. Filter precisely in
  the Lambda instead.
- Don't restore `get_recent_events` / `filter_log_events` / `LOOKBACK_MINUTES`
  (the pre-flip enrichment path that lost the ingestion-lag race).
