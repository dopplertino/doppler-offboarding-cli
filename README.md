# Doppler User Offboarder

Automates the AWS credential cleanup step of offboarding a Doppler user.

It scans the Doppler workplace activity log for every dynamic AWS IAM user that person ever leased, then deletes those IAM users directly from AWS — revoking their access keys and inline policies in the process.

## Why this exists

Doppler's dynamic secrets automatically expire (default TTL: 30 minutes), but if Doppler's cleanup job fails for any reason, the IAM user can be orphaned in AWS — indefinitely active even though the lease is gone. During offboarding you want certainty, not reliance on eventual cleanup.

This script gives you a complete, auditable list of every IAM credential that person created, and deletes them with a two-phase workflow that protects production environments.

## How it works

| Phase | What happens |
|---|---|
| **1 — Scan** | Paginates through the Doppler workplace activity log and finds every `Issued a lease` event attributed to the user |
| **2 — Non-prod** | Deletes the IAM users from dev / staging environments immediately |
| **3 — Prod** | Lists all production IAM users, warns explicitly, and requires typing the user's email to confirm before deleting |

For each IAM user the script:
1. Lists and deletes all access keys (immediate credential revocation)
2. Deletes all inline policies
3. Deletes the IAM user

## Prerequisites

**Doppler**
- A personal access token with **View All Logs** (`logs_audit`) permission
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

Shows every IAM user that would be touched — no changes made.

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com
```

### 2. Delete (interactive prod confirmation)

Non-prod IAM users are deleted automatically. Prod IAM users are listed and you must type the user's email to confirm.

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete
```

### 3. Skip prod (delete non-prod only)

Useful if prod needs a separate approval process.

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete --skip-prod
```

### 4. Force prod (non-interactive, for CI/automation)

Deletes everything including prod without a prompt. Use with caution.

```bash
DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete --force-prod
```

## Options

| Flag | Description |
|---|---|
| `--user` | **(Required)** Email of the user being offboarded |
| `--delete` | Apply deletions. Without this flag the script is a read-only dry run |
| `--skip-prod` | Skip all credentials from production environments |
| `--force-prod` | Delete prod credentials without interactive confirmation |
| `--max-pages` | Limit log pages scanned (20 entries/page). Default: all available |
| `--dump-unparsed` | Print raw JSON for any log entries the parser couldn't read |

## Log retention limits

The script can only see activity logs within your plan's retention window:

| Plan | Log history |
|---|---|
| Developer | 3 days |
| Team | 90 days |
| Enterprise | 1,095 days (3 years) |

For offboarding, run this script **before** removing the user from Doppler — otherwise their log entries may become inaccessible.

## Production environment detection

The following environment names are treated as production and trigger the warning + confirmation prompt:

`prd`, `prod`, `production`, `live`, `release`

To add custom names, edit `PROD_ENV_NAMES` at the top of `offboard.py`.

## What it does NOT do

- Remove the user from Doppler (do this in the Doppler dashboard)
- Revoke Doppler service tokens or personal tokens belonging to the user
- Rotate secrets the user had access to (consider doing this for high-value secrets)
- Handle Doppler-managed rotated secrets (those are static IAM users managed separately)
