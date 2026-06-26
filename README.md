# Doppler User Offboarder

Automates the credential-cleanup step of offboarding a Doppler user.

Scans the Doppler workplace activity log for every credential action that person ever took, then lets you revoke/delete them in a safe, auditable workflow.

## What it covers

| Credential type | How it's found | Action |
|---|---|---|
| Dynamic AWS IAM users | Activity log — `Issued a lease` events | Delete access keys → inline policies → IAM user |
| Service tokens | Activity log — `Created service token` events | List active tokens in those configs + interactive revocation |
| High-entropy secrets | Fetch secrets from all accessed configs | Add rotate-me note via Doppler API |

## Why this exists

Doppler's dynamic secrets automatically expire (default TTL: 30 minutes), but if Doppler's cleanup job fails, the IAM user can be orphaned in AWS — indefinitely active even though the lease is gone. Service tokens have no expiry unless explicitly revoked. During offboarding you want certainty, not reliance on eventual cleanup.

This script gives you a complete, auditable list of every credential that person created, and handles them through a phased workflow that protects production environments.

## How it works

| Phase | What happens |
|---|---|
| **1 — Scan** | Paginates through the Doppler workplace activity log, finds all events attributed to the user |
| **2 — Report** | Builds a table of every project/config the user accessed with last-seen timestamps |
| **3 — Service tokens** | Finds configs where the user created service tokens, lists current active tokens, prompts to revoke each one |
| **4 — Non-prod IAM** | Deletes dynamic IAM users from dev/staging environments automatically |
| **5 — Prod IAM** | Lists prod IAM users, warns explicitly, requires y/n confirmation per credential |
| **6 — Secret scan** | _(opt-in)_ Scans secrets in accessed configs for high-entropy values, lets you add rotate-me notes |

For each dynamic IAM user the script:
1. Lists and deletes all access keys (immediate credential revocation)
2. Deletes all inline policies
3. Deletes the IAM user

## Prerequisites

**Doppler**
- A personal access token with **View All Logs** (`logs_audit`) permission
- For service token revocation: also needs **Manage Service Tokens** on affected projects
- For secret scanning: also needs **View Secrets** on affected projects
- Generate one at: `https://dashboard.doppler.com/workplace/settings/tokens`

**AWS**
- `aws` CLI installed and configured
- IAM permissions: `iam:ListAccessKeys`, `iam:DeleteAccessKey`, `iam:ListUserPolicies`, `iam:DeleteUserPolicy`, `iam:DeleteUser`

**Python**
```bash
pip install requests
```

## Usage

### 1. Dry run (always start here)

Shows every credential that would be touched — no changes made.

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com
```

### 2. Full interactive offboarding

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete
```

Non-prod IAM users are deleted automatically. Service tokens and prod IAM users require y/n confirmation per credential.

### 3. Limit the log search window

```bash
# Last 90 days
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --days 90

# Since a specific date
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --since 2024-01-01
```

### 4. Scan secrets for high-entropy values (likely API keys)

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --scan-secrets
```

For each config the user accessed, fetches secrets and flags values with high Shannon entropy (likely API keys, tokens, or random secrets). Lets you add a "rotate-me" note to each flagged secret via the Doppler API — the note will be visible in the Doppler dashboard on that secret.

> **Note:** Doppler secret notes are project-scoped (apply to a secret name across all configs in the project).

> **No rotation API:** Doppler's "Rotate now" button has no public API equivalent. This tool flags secrets with a note as the next-best option — rotate them manually from the dashboard or CLI after offboarding.

### 5. Skip or force prod

```bash
# Skip prod credentials entirely
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete --skip-prod

# Force delete everything including prod — no prompts (CI/automation)
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete --force-prod
```

## Options

| Flag | Description |
|---|---|
| `--user` | **(Required)** Email of the user being offboarded |
| `--delete` | Apply revocations/deletions. Without this the script is read-only. |
| `--skip-prod` | Skip all credentials from production environments |
| `--force-prod` | Delete/revoke prod credentials without interactive confirmation |
| `--since YYYY-MM-DD` | Only scan logs on or after this date |
| `--days N` | Only scan logs from the last N days |
| `--max-pages N` | Limit log pages scanned (20 entries/page). Default: all available |
| `--scan-secrets` | Scan secrets in accessed configs for high-entropy values |
| `--entropy-threshold BITS` | Shannon entropy threshold for flagging secrets (default: 3.5). Random hex ≈ 4.0, base64 ≈ 6.0 |
| `--min-secret-length N` | Minimum secret length to consider for entropy scan (default: 24) |
| `--dump-unparsed` | Print raw JSON for lease log entries that couldn't be parsed |

## Log retention limits

The script can only see activity within your plan's retention window:

| Plan | Log history |
|---|---|
| Developer | 3 days |
| Team | 90 days |
| Enterprise | 1,095 days (3 years) |

**Run this script before removing the user from Doppler** — their log entries may become inaccessible once they're removed.

Use `--days` or `--since` to limit the scan if you only care about recent activity (faster and cheaper on the API).

## Production environment detection

The following environment names trigger warnings and require confirmation:

`prd`, `prod`, `production`, `live`, `release`

To add custom names, edit `PROD_ENV_NAMES` at the top of `offboard.py`.

## Service token limitations

The Doppler API does not include a `created_by` field in the service token list response. The script detects which **configs** a user created tokens in via the activity log, then lists all currently active tokens in those configs. It cannot definitively say which specific token the user created if there are multiple — it hints based on the token name when it can be parsed from the log text.

## What it does NOT do

- Remove the user from Doppler (do this in the Doppler dashboard after running this script)
- Revoke Doppler personal tokens or CLI tokens belonging to the user
- Trigger automatic rotation of rotated secrets (no public API — use the dashboard "Rotate now" button)
- Handle Doppler-managed rotated secrets (those are static IAM users managed separately by Doppler)
- Enumerate service accounts (workplace-level) — only config-level service tokens
