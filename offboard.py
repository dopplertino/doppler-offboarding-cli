#!/usr/bin/env python3
"""
Doppler User Offboarder
-----------------------
Scans Doppler activity logs to find all dynamic AWS IAM credentials
created by a specific user, then deletes them from AWS directly.

Workflow:
  Phase 1 — Scan:    Fetch all activity logs, find lease events for the user
  Phase 2 — Non-prod: Delete IAM users from non-production environments
  Phase 3 — Prod:    Warn, list prod IAM users, require explicit confirmation

Usage:
  # Dry run (safe — no changes made)
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com

  # Delete everything (prompts for prod confirmation interactively)
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete

  # Skip prod environments entirely
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete --skip-prod

  # Delete everything including prod without interactive prompt (CI/automation)
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete --force-prod

  # Limit how many log pages to scan (20 entries/page, 0 = all available)
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --max-pages 100

Requirements:
  pip install requests
  aws CLI configured with iam:ListAccessKeys, iam:DeleteAccessKey,
                           iam:ListUserPolicies, iam:DeleteUserPolicy,
                           iam:DeleteUser
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

BASE_URL = "https://api.doppler.com/v3"

# Environment names considered production — warn before deleting
PROD_ENV_NAMES = {"prd", "prod", "production", "live", "release"}


# ── ANSI colours ──────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[0;31m"
    YELLOW = "\033[1;33m"
    GREEN  = "\033[0;32m"
    CYAN   = "\033[0;36m"
    BLUE   = "\033[0;34m"

def log(msg):    print(f"{C.CYAN}[info]{C.RESET}  {msg}")
def warn(msg):   print(f"{C.YELLOW}[warn]{C.RESET}  {msg}")
def ok(msg):     print(f"{C.GREEN}[ok]{C.RESET}    {msg}")
def err(msg):    print(f"{C.RED}[error]{C.RESET} {msg}", file=sys.stderr)
def dim(msg):    print(f"{C.DIM}{msg}{C.RESET}")
def bold(msg):   print(f"{C.BOLD}{msg}{C.RESET}")


# ── Doppler API ───────────────────────────────────────────────────────────────

def doppler_get(token, path, params=None):
    resp = requests.get(
        f"{BASE_URL}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_all_logs(token, max_pages):
    all_logs = []
    page = 1
    per_page = 20
    while True:
        if max_pages and page > max_pages:
            warn(f"Reached --max-pages limit ({max_pages}). Stopping scan early.")
            break
        try:
            data = doppler_get(token, "/logs", {"page": page, "per_page": per_page})
        except requests.HTTPError as exc:
            err(f"Failed to fetch logs page {page}: {exc}")
            break
        entries = data.get("logs", [])
        if not entries:
            break
        all_logs.extend(entries)
        if len(entries) < per_page:
            break
        page += 1
        time.sleep(0.1)
    return all_logs


# ── Log parsing ───────────────────────────────────────────────────────────────

_AWS_USERNAME_RE  = re.compile(r"Doppler-Dynamic-[A-Za-z0-9]+")
_DYNAMIC_SECRET_RE = re.compile(r"for dynamic secret\s+([A-Za-z0-9_]+)", re.IGNORECASE)


def extract_user_email(entry):
    user = entry.get("user") or {}
    if isinstance(user, dict):
        return user.get("email") or user.get("name") or user.get("username")
    return entry.get("user_email") or entry.get("actor_email")


def is_lease_event(entry):
    text = (entry.get("text") or entry.get("html") or "").lower()
    event_type = (entry.get("type") or entry.get("event") or "").lower()
    keywords = ["dynamic", "lease", "leased", "dynamic secret", "aws iam"]
    return any(kw in text or kw in event_type for kw in keywords)


def is_prod(entry):
    env = (entry.get("enclave_environment") or "").lower().strip()
    return env in PROD_ENV_NAMES


def parse_lease(entry):
    """Return a structured dict from a log entry, or None if we can't parse it."""
    aws_username = None
    blob = json.dumps(entry, default=str)
    m = _AWS_USERNAME_RE.search(blob)
    if m:
        aws_username = m.group(0)

    # No IAM user in the log — nothing to delete in AWS
    if not aws_username:
        return None

    project = entry.get("enclave_project") or entry.get("project")
    config  = entry.get("enclave_config")  or entry.get("config")
    env     = entry.get("enclave_environment") or entry.get("environment") or "unknown"

    text = entry.get("text") or ""
    ds_match = _DYNAMIC_SECRET_RE.search(text)
    dynamic_secret = ds_match.group(1) if ds_match else "unknown"

    return {
        "log_id":         entry.get("id", "?"),
        "created_at":     entry.get("created_at", "?"),
        "aws_username":   aws_username,
        "project":        project or "unknown",
        "config":         config  or "unknown",
        "environment":    env,
        "dynamic_secret": dynamic_secret,
        "is_prod":        is_prod(entry),
    }


# ── AWS IAM cleanup ───────────────────────────────────────────────────────────

def aws(*args, capture=True):
    """Run an AWS CLI command. Returns (success, output)."""
    cmd = ["aws"] + list(args) + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, timeout=30)
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, result.stdout.strip()
    except FileNotFoundError:
        return False, "aws CLI not found"
    except subprocess.TimeoutExpired:
        return False, "timed out"


def delete_iam_user(username, dry_run):
    """
    Delete a Doppler-Dynamic IAM user:
      1. Delete all access keys   (immediate credential revocation)
      2. Delete all inline policies
      3. Delete the user
    Returns True on success (or dry run).
    """
    if dry_run:
        dim(f"    [dry-run] Would delete access keys, inline policies, and user: {username}")
        return True

    # 1. List + delete access keys
    ok_keys, keys_out = aws("iam", "list-access-keys", "--user-name", username)
    if not ok_keys:
        if "NoSuchEntity" in keys_out or "cannot be found" in keys_out:
            warn(f"    IAM user not found in AWS — already deleted or TTL-expired and cleaned.")
            return True
        err(f"    Could not list access keys: {keys_out}")
        return False

    try:
        key_ids = [k["AccessKeyId"] for k in json.loads(keys_out).get("AccessKeyMetadata", [])]
    except (json.JSONDecodeError, KeyError):
        key_ids = []

    for key_id in key_ids:
        print(f"    Deleting access key : {key_id}")
        ok_del, del_out = aws("iam", "delete-access-key",
                              "--user-name", username, "--access-key-id", key_id)
        if not ok_del:
            err(f"    Failed to delete key {key_id}: {del_out}")

    if not key_ids:
        dim("    No access keys found.")

    # 2. List + delete inline policies
    ok_pol, pol_out = aws("iam", "list-user-policies", "--user-name", username)
    try:
        policy_names = json.loads(pol_out).get("PolicyNames", []) if ok_pol else []
    except json.JSONDecodeError:
        policy_names = []

    for policy_name in policy_names:
        print(f"    Deleting inline policy : {policy_name}")
        ok_pdel, pdel_out = aws("iam", "delete-user-policy",
                                "--user-name", username, "--policy-name", policy_name)
        if not ok_pdel:
            err(f"    Failed to delete policy {policy_name}: {pdel_out}")

    if not policy_names:
        dim("    No inline policies found.")

    # 3. Delete user
    print(f"    Deleting IAM user : {username}")
    ok_usr, usr_out = aws("iam", "delete-user", "--user-name", username)
    if not ok_usr:
        err(f"    Failed to delete user: {usr_out}")
        return False

    return True


# ── Display helpers ───────────────────────────────────────────────────────────

def lease_age_str(created_at_str):
    """Return human-readable age and whether the 30-min TTL has likely expired."""
    try:
        created = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - created
        total_mins = int(delta.total_seconds() / 60)
        if total_mins < 60:
            age = f"{total_mins}m ago"
        elif total_mins < 1440:
            age = f"{total_mins // 60}h {total_mins % 60}m ago"
        else:
            age = f"{total_mins // 1440}d ago"
        expired = total_mins >= 30
        return age, expired
    except Exception:
        return created_at_str, None


def print_lease(lease, index=None, total=None):
    prefix = f"[{index}/{total}] " if index is not None else ""
    env_label = lease["environment"].upper()
    env_colour = C.RED if lease["is_prod"] else C.CYAN
    age, expired = lease_age_str(lease["created_at"])
    if expired is True:
        expiry_str = f"{C.DIM}lease TTL expired (~{age}){C.RESET}"
    elif expired is False:
        expiry_str = f"{C.YELLOW}lease may still be active ({age}){C.RESET}"
    else:
        expiry_str = age
    print(f"\n{C.CYAN}{'─' * 58}{C.RESET}")
    print(f"  {prefix}{env_colour}{C.BOLD}{env_label}{C.RESET}  —  {lease['aws_username']}")
    print(f"  Project : {lease['project']}  /  Config : {lease['config']}")
    print(f"  Secret  : {lease['dynamic_secret']}")
    print(f"  Leased  : {lease['created_at']}  ({expiry_str})")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Offboard a Doppler user by deleting their dynamic AWS IAM credentials."
    )
    parser.add_argument("--user",       required=True,
                        help="Email of the user being offboarded")
    parser.add_argument("--delete",     action="store_true",
                        help="Actually delete IAM users (default: dry run)")
    parser.add_argument("--skip-prod",  action="store_true",
                        help="Skip credentials from production environments entirely")
    parser.add_argument("--force-prod", action="store_true",
                        help="Delete prod credentials without interactive confirmation (for CI)")
    parser.add_argument("--max-pages",  type=int, default=0,
                        help="Max log pages to scan (20 entries/page, 0 = all available)")
    parser.add_argument("--dump-unparsed", action="store_true",
                        help="Print raw JSON for any log entries that couldn't be parsed")
    args = parser.parse_args()

    token = os.environ.get("DOPPLER_TOKEN")
    if not token:
        err("DOPPLER_TOKEN is not set.")
        err("Generate a personal token at: https://dashboard.doppler.com/workplace/settings/tokens")
        sys.exit(1)

    if not shutil.which("aws"):
        err("aws CLI not found in PATH. Install it and configure credentials first.")
        sys.exit(1)

    dry_run = not args.delete

    print()
    bold(f"  Doppler User Offboarder")
    print(f"  {'─' * 40}")
    log(f"User       : {C.BOLD}{args.user}{C.RESET}")
    log(f"Mode       : {'DRY RUN — no changes will be made' if dry_run else f'{C.RED}{C.BOLD}LIVE — IAM users will be deleted{C.RESET}'}")
    log(f"Prod envs  : {'skip' if args.skip_prod else 'force-delete (no prompt)' if args.force_prod else 'prompt for confirmation'}")
    log(f"Log pages  : {args.max_pages if args.max_pages else 'all available'}")
    print()

    # ── Phase 1: Scan ─────────────────────────────────────────────────────────
    print(f"{C.BOLD}Phase 1 — Scanning activity logs{C.RESET}")
    print(f"  {'─' * 40}")
    log("Fetching logs...")
    all_logs = fetch_all_logs(token, args.max_pages)
    log(f"Total log entries fetched : {len(all_logs)}")

    user_logs = [e for e in all_logs
                 if args.user.lower() in (extract_user_email(e) or "").lower()]
    log(f"Entries for '{args.user}'  : {len(user_logs)}")

    lease_logs = [e for e in user_logs if is_lease_event(e)]
    log(f"Dynamic lease events      : {len(lease_logs)}")
    print()

    if not lease_logs:
        ok("No dynamic lease events found for this user. Nothing to clean up.")
        sys.exit(0)

    # Parse each lease event into a structured record
    leases = []
    unparsed = []
    for entry in lease_logs:
        parsed = parse_lease(entry)
        if parsed:
            leases.append(parsed)
        else:
            unparsed.append(entry)

    if unparsed:
        warn(f"{len(unparsed)} lease event(s) had no IAM username — skipped.")
        if args.dump_unparsed:
            for e in unparsed:
                print(json.dumps(e, indent=2, default=str))

    non_prod_leases = [l for l in leases if not l["is_prod"]]
    prod_leases     = [l for l in leases if l["is_prod"]]

    log(f"IAM users to process : {len(leases)} total  "
        f"({len(non_prod_leases)} non-prod, {C.RED}{len(prod_leases)} prod{C.RESET})")
    print()

    # ── Phase 2: Non-prod ─────────────────────────────────────────────────────
    non_prod_deleted = 0
    non_prod_failed  = 0

    if non_prod_leases:
        print(f"{C.BOLD}Phase 2 — Non-production IAM users ({len(non_prod_leases)}){C.RESET}")
        print(f"  {'─' * 40}")
        for i, lease in enumerate(non_prod_leases, 1):
            print_lease(lease, i, len(non_prod_leases))
            success = delete_iam_user(lease["aws_username"], dry_run)
            if success:
                if not dry_run:
                    ok(f"    Deleted.")
                non_prod_deleted += 1
            else:
                non_prod_failed += 1
        print()
    else:
        print(f"{C.BOLD}Phase 2 — Non-production IAM users{C.RESET}")
        dim("  None found.")
        print()

    # ── Phase 3: Prod ─────────────────────────────────────────────────────────
    prod_deleted = 0
    prod_failed  = 0
    prod_skipped = 0

    print(f"{C.BOLD}Phase 3 — Production IAM users ({len(prod_leases)}){C.RESET}")
    print(f"  {'─' * 40}")

    if not prod_leases:
        dim("  None found.")
        print()
    elif args.skip_prod:
        warn(f"  --skip-prod set. Skipping all {len(prod_leases)} prod credential(s).")
        warn("  Re-run without --skip-prod to handle them.")
        prod_skipped = len(prod_leases)
        print()
    else:
        # Show all prod leases first so the user sees everything before deciding
        print()
        print(f"  {C.RED}{C.BOLD}⚠  WARNING — production environment credentials detected{C.RESET}")
        print(f"  {C.RED}Deleting these will immediately revoke access to production AWS resources.{C.RESET}")
        print(f"  {C.RED}Verify the user has been fully removed from all systems before proceeding.{C.RESET}")
        print()

        for i, lease in enumerate(prod_leases, 1):
            print_lease(lease, i, len(prod_leases))
        print()

        for i, lease in enumerate(prod_leases, 1):
            print_lease(lease, i, len(prod_leases))
            print()

            if dry_run:
                dim(f"  [dry-run] Would prompt: delete {lease['aws_username']}? (y/n)")
                prod_deleted += 1
                continue

            if args.force_prod:
                warn("  --force-prod set — auto-confirming.")
                do_delete = True
            else:
                _, expired = lease_age_str(lease["created_at"])
                expiry_note = (
                    "lease TTL has expired but IAM user may still exist in AWS"
                    if expired else
                    f"{C.YELLOW}lease may still be active — deleting will immediately revoke access{C.RESET}"
                )
                print(f"  {C.RED}{C.BOLD}PROD — {lease['project']} / {lease['config']}{C.RESET}")
                print(f"  {expiry_note}")
                print(f"  Delete {C.BOLD}{lease['aws_username']}{C.RESET}? [y/n] ", end="", flush=True)
                try:
                    answer = input().strip().lower()
                except (KeyboardInterrupt, EOFError):
                    print()
                    warn("  Aborted.")
                    prod_skipped += len(prod_leases) - (i - 1)
                    break
                do_delete = answer in ("y", "yes")

            if do_delete:
                success = delete_iam_user(lease["aws_username"], dry_run=False)
                if success:
                    ok(f"    Deleted.")
                    prod_deleted += 1
                else:
                    prod_failed += 1
            else:
                warn(f"  Skipped {lease['aws_username']}.")
                prod_skipped += 1
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"{C.CYAN}{'═' * 58}{C.RESET}")
    bold("  Summary")
    print(f"  {'─' * 40}")
    print(f"  Lease events found        : {len(leases)}")
    print()
    print(f"  Non-prod IAM users {'deleted' if not dry_run else 'found'}   : {non_prod_deleted}")
    if non_prod_failed:
        print(f"  Non-prod failures         : {non_prod_failed}")
    print()
    print(f"  Prod IAM users {'deleted' if not dry_run else 'found'}       : {prod_deleted}")
    if prod_skipped:
        print(f"  Prod users skipped        : {prod_skipped}  (re-run to handle)")
    if prod_failed:
        print(f"  Prod failures             : {prod_failed}")

    if dry_run:
        print()
        warn("Dry run — no changes were made. Re-run with --delete to apply.")
    print()


if __name__ == "__main__":
    main()
