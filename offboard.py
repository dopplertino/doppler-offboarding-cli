#!/usr/bin/env python3
"""
Doppler User Offboarder
-----------------------
Scans Doppler activity logs to find all credentials associated with a specific
user, then allows you to revoke/delete them as part of offboarding.

Phases:
  1 — Scan        Fetch activity logs, find all actions by the user
  2 — Report      Projects & configs the user accessed (last-seen timestamps)
  3 — Svc tokens  Service tokens the user created — list + optional revocation
  4 — Non-prod    Delete dynamic AWS IAM users from non-production environments
  5 — Prod        Warn and prompt before deleting prod dynamic IAM users
  6 — Secrets     Scan accessed configs for high-entropy values (--scan-secrets)

Usage:
  # Dry run (safe — no changes made)
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com

  # Full interactive offboarding
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete

  # Limit log search to last 30 days
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --days 30

  # Also scan for high-entropy secrets (likely API keys) and add rotate-me notes
  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --scan-secrets

Requirements:
  pip install requests
  aws CLI configured with:  iam:ListAccessKeys  iam:DeleteAccessKey
                            iam:ListUserPolicies iam:DeleteUserPolicy iam:DeleteUser
"""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

BASE_URL = "https://api.doppler.com/v3"

# Environment names treated as production — trigger warnings / confirmation
PROD_ENV_NAMES = {"prd", "prod", "production", "live", "release"}

# Defaults for the high-entropy secret scanner
DEFAULT_ENTROPY_THRESHOLD = 3.5   # bits/char  (random hex ≈ 4.0, base64 ≈ 6.0)
DEFAULT_MIN_SECRET_LENGTH = 24    # characters


# ── ANSI colours ──────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[0;31m"
    YELLOW  = "\033[1;33m"
    GREEN   = "\033[0;32m"
    CYAN    = "\033[0;36m"
    BLUE    = "\033[0;34m"
    MAGENTA = "\033[0;35m"


def log(msg):   print(f"{C.CYAN}[info]{C.RESET}  {msg}")
def warn(msg):  print(f"{C.YELLOW}[warn]{C.RESET}  {msg}")
def ok(msg):    print(f"{C.GREEN}[ok]{C.RESET}    {msg}")
def err(msg):   print(f"{C.RED}[error]{C.RESET} {msg}", file=sys.stderr)
def dim(msg):   print(f"{C.DIM}{msg}{C.RESET}")
def bold(msg):  print(f"{C.BOLD}{msg}{C.RESET}")


def section(title):
    print(f"{C.BOLD}{title}{C.RESET}")
    print(f"  {'─' * 44}")


# ── Doppler API ───────────────────────────────────────────────────────────────

def _auth_headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def doppler_get(token, path, params=None):
    resp = requests.get(
        f"{BASE_URL}{path}",
        headers=_auth_headers(token),
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def doppler_post(token, path, body):
    resp = requests.post(
        f"{BASE_URL}{path}",
        headers={**_auth_headers(token), "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def doppler_delete(token, path, body=None):
    resp = requests.delete(
        f"{BASE_URL}{path}",
        headers={**_auth_headers(token), "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_all_logs(token, max_pages, since=None):
    """
    Paginate GET /v3/logs (newest-first).
    Stops early when max_pages is reached or all entries are older than `since`.
    """
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

        if since is not None:
            filtered = []
            hit_cutoff = False
            for e in entries:
                try:
                    dt = datetime.fromisoformat(
                        (e.get("created_at") or "").replace("Z", "+00:00")
                    )
                    if dt < since:
                        hit_cutoff = True
                        continue
                except Exception:
                    pass
                filtered.append(e)
            all_logs.extend(filtered)
            if hit_cutoff:
                break
        else:
            all_logs.extend(entries)

        if len(entries) < per_page:
            break
        page += 1
        time.sleep(0.1)

    return all_logs


# ── Log parsing ───────────────────────────────────────────────────────────────

_AWS_USERNAME_RE   = re.compile(r"Doppler-Dynamic-[A-Za-z0-9]+")
_DYNAMIC_SECRET_RE = re.compile(r"for dynamic secret\s+([A-Za-z0-9_\-]+)", re.IGNORECASE)
# Matches patterns like: "service token 'my-token'" or "service token: my-token"
_SVC_TOKEN_NAME_RE = re.compile(
    r"service token[:\s]+['\"]?([A-Za-z0-9_\- ]+)['\"]?", re.IGNORECASE
)


def extract_user_email(entry):
    user = entry.get("user") or {}
    if isinstance(user, dict):
        return user.get("email") or user.get("name") or user.get("username")
    return entry.get("user_email") or entry.get("actor_email")


def is_lease_event(entry):
    text       = (entry.get("text") or entry.get("html") or "").lower()
    event_type = (entry.get("type") or entry.get("event") or "").lower()
    keywords   = ["dynamic", "lease", "leased", "dynamic secret", "aws iam"]
    return any(kw in text or kw in event_type for kw in keywords)


def is_service_token_event(entry):
    """True if this log entry records a service token being created."""
    text = (entry.get("text") or entry.get("html") or "").lower()
    return "service token" in text and any(
        kw in text for kw in ("creat", "generat", "add")
    )


def is_prod_env(env_name):
    return (env_name or "").lower().strip() in PROD_ENV_NAMES


def _project_config_env(entry):
    project = entry.get("enclave_project") or entry.get("project") or "unknown"
    config  = entry.get("enclave_config")  or entry.get("config")  or "unknown"
    env     = entry.get("enclave_environment") or entry.get("environment") or "unknown"
    return project, config, env


def parse_lease(entry):
    """Return a structured dict from a lease log entry, or None."""
    blob = json.dumps(entry, default=str)
    m = _AWS_USERNAME_RE.search(blob)
    if not m:
        return None
    aws_username = m.group(0)

    project, config, env = _project_config_env(entry)
    text     = entry.get("text") or ""
    ds_match = _DYNAMIC_SECRET_RE.search(text)

    return {
        "log_id":         entry.get("id", "?"),
        "created_at":     entry.get("created_at", "?"),
        "aws_username":   aws_username,
        "project":        project,
        "config":         config,
        "environment":    env,
        "dynamic_secret": ds_match.group(1) if ds_match else "unknown",
        "is_prod":        is_prod_env(env),
    }


def parse_service_token_event(entry):
    """Extract metadata from a service-token-creation log entry."""
    project, config, env = _project_config_env(entry)
    text = entry.get("text") or ""
    m    = _SVC_TOKEN_NAME_RE.search(text)
    return {
        "project":    project,
        "config":     config,
        "environment": env,
        "is_prod":    is_prod_env(env),
        "created_at": entry.get("created_at", "?"),
        "token_name": m.group(1).strip() if m else None,
        "log_text":   text,
    }


def build_access_report(user_logs):
    """
    Aggregate all log entries by (project, config) and record the most recent
    access timestamp and total event count.
    Returns dict keyed by (project, config).
    """
    report = {}
    for entry in user_logs:
        project, config, env = _project_config_env(entry)
        if project == "unknown":
            continue
        key = (project, config)
        try:
            dt = datetime.fromisoformat(
                (entry.get("created_at") or "").replace("Z", "+00:00")
            )
        except Exception:
            dt = None

        if key not in report:
            report[key] = {
                "project":     project,
                "config":      config,
                "environment": env,
                "is_prod":     is_prod_env(env),
                "last_seen":   dt,
                "event_count": 0,
            }
        meta = report[key]
        if dt and (meta["last_seen"] is None or dt > meta["last_seen"]):
            meta["last_seen"] = dt
        meta["event_count"] += 1
    return report


# ── Service token operations ──────────────────────────────────────────────────

def fetch_service_tokens(token, project, config):
    """
    List active service tokens for a project/config.
    Returns list of token dicts, None if no access, or [] on other errors.
    """
    try:
        data = doppler_get(token, "/configs/config/tokens",
                           {"project": project, "config": config})
        return data.get("tokens", [])
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code in (401, 403):
            return None
        err(f"    Failed to list tokens for {project}/{config}: {exc}")
        return []


def revoke_service_token(token, project, config, slug, dry_run):
    """Delete (revoke) a service token. Returns True on success."""
    if dry_run:
        dim(f"      [dry-run] Would revoke token slug={slug[:12]}... in {project}/{config}")
        return True
    try:
        doppler_delete(token, "/configs/config/tokens/token",
                       {"project": project, "config": config, "slug": slug})
        return True
    except requests.HTTPError as exc:
        err(f"      Failed to revoke token {slug}: {exc}")
        return False


# ── Secrets / entropy scanning ────────────────────────────────────────────────

def fetch_secrets(token, project, config):
    """
    Fetch secrets with their computed values for a project/config.
    Returns {name: value} or None if no access (403/401).
    """
    try:
        data = doppler_get(token, "/configs/config/secrets",
                           {"project": project, "config": config,
                            "include_dynamic_secrets": "false",
                            "include_managed_secrets": "true"})
        return {
            name: (info.get("computed") or info.get("raw") or "")
            for name, info in data.get("secrets", {}).items()
        }
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code in (401, 403):
            return None
        err(f"    Failed to fetch secrets for {project}/{config}: {exc}")
        return {}


def shannon_entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_high_entropy(value, threshold, min_length):
    """Return True if value is likely a random API key / secret token."""
    if not value or len(value) < min_length:
        return False
    # Skip values that are clearly not API keys
    if " " in value or "\n" in value:
        return False
    if value.startswith(("http://", "https://", "/")):
        return False
    return shannon_entropy(value) >= threshold


# ── AWS IAM cleanup ───────────────────────────────────────────────────────────

def aws_cmd(*args, capture=True):
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
      1. Delete all access keys  (immediate credential revocation)
      2. Delete all inline policies
      3. Delete the user
    Returns True on success or dry run.
    """
    if dry_run:
        dim(f"    [dry-run] Would delete access keys, inline policies, and user: {username}")
        return True

    # 1. Access keys
    ok_keys, keys_out = aws_cmd("iam", "list-access-keys", "--user-name", username)
    if not ok_keys:
        if "NoSuchEntity" in keys_out or "cannot be found" in keys_out:
            warn(f"    IAM user not found in AWS — already deleted or TTL-expired.")
            return True
        err(f"    Could not list access keys: {keys_out}")
        return False

    try:
        key_ids = [k["AccessKeyId"]
                   for k in json.loads(keys_out).get("AccessKeyMetadata", [])]
    except (json.JSONDecodeError, KeyError):
        key_ids = []

    for key_id in key_ids:
        print(f"    Deleting access key : {key_id}")
        ok_del, del_out = aws_cmd("iam", "delete-access-key",
                                  "--user-name", username, "--access-key-id", key_id)
        if not ok_del:
            err(f"    Failed to delete key {key_id}: {del_out}")

    if not key_ids:
        dim("    No access keys found.")

    # 2. Inline policies
    ok_pol, pol_out = aws_cmd("iam", "list-user-policies", "--user-name", username)
    try:
        policy_names = json.loads(pol_out).get("PolicyNames", []) if ok_pol else []
    except json.JSONDecodeError:
        policy_names = []

    for policy_name in policy_names:
        print(f"    Deleting inline policy : {policy_name}")
        ok_pdel, pdel_out = aws_cmd("iam", "delete-user-policy",
                                    "--user-name", username, "--policy-name", policy_name)
        if not ok_pdel:
            err(f"    Failed to delete policy {policy_name}: {pdel_out}")

    if not policy_names:
        dim("    No inline policies found.")

    # 3. User
    print(f"    Deleting IAM user : {username}")
    ok_usr, usr_out = aws_cmd("iam", "delete-user", "--user-name", username)
    if not ok_usr:
        err(f"    Failed to delete user: {usr_out}")
        return False

    return True


# ── Display helpers ───────────────────────────────────────────────────────────

def format_dt(dt):
    if dt is None:
        return "unknown"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def lease_age_str(created_at_str):
    try:
        created    = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        now        = datetime.now(timezone.utc)
        total_mins = int((now - created).total_seconds() / 60)
        if total_mins < 60:
            age = f"{total_mins}m ago"
        elif total_mins < 1440:
            age = f"{total_mins // 60}h {total_mins % 60}m ago"
        else:
            age = f"{total_mins // 1440}d ago"
        return age, total_mins >= 30
    except Exception:
        return created_at_str, None


def print_lease(lease, index=None, total=None):
    prefix     = f"[{index}/{total}] " if index is not None else ""
    age, expired = lease_age_str(lease["created_at"])
    env_colour = C.RED if lease["is_prod"] else C.CYAN
    if expired is True:
        expiry_str = f"{C.DIM}lease TTL expired (~{age}){C.RESET}"
    elif expired is False:
        expiry_str = f"{C.YELLOW}lease may still be active ({age}){C.RESET}"
    else:
        expiry_str = age
    print(f"\n{C.CYAN}{'─' * 60}{C.RESET}")
    print(f"  {prefix}{env_colour}{C.BOLD}{lease['environment'].upper()}{C.RESET}"
          f"  —  {lease['aws_username']}")
    print(f"  Project : {lease['project']}  /  Config : {lease['config']}")
    print(f"  Secret  : {lease['dynamic_secret']}")
    print(f"  Leased  : {lease['created_at']}  ({expiry_str})")


def prompt_yn(prompt_text):
    """Prompt the user for y/n. Returns True for yes. Raises KeyboardInterrupt on abort."""
    print(f"  {prompt_text} [y/n] ", end="", flush=True)
    try:
        return input().strip().lower() in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        raise KeyboardInterrupt


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="offboard.py",
        description=(
            "Audit and revoke Doppler credentials for an offboarded user.\n\n"
            "Always start with a dry run (no flags other than --user) to review\n"
            "what will be touched, then re-run with --delete to apply changes.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  # Dry run — see everything, change nothing\n"
            "  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com\n\n"
            "  # Interactive delete (prompts for prod + service tokens)\n"
            "  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --delete\n\n"
            "  # Limit to last 90 days of logs\n"
            "  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --days 90\n\n"
            "  # Scan secrets in accessed configs for high-entropy values\n"
            "  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com --scan-secrets\n\n"
            "  # Non-interactive prod deletion (CI/automation)\n"
            "  DOPPLER_TOKEN=dp.pt.xxx python3 offboard.py --user alice@example.com "
            "--delete --force-prod\n"
        ),
    )

    parser.add_argument(
        "--user", required=True,
        help="Email of the user being offboarded",
    )
    parser.add_argument(
        "--delete", action="store_true",
        help="Apply revocations/deletions. Without this flag the script is read-only.",
    )
    parser.add_argument(
        "--skip-prod", action="store_true",
        help="Skip all credentials from production environments entirely",
    )
    parser.add_argument(
        "--force-prod", action="store_true",
        help="Delete prod credentials without interactive confirmation (for CI/automation)",
    )

    grp = parser.add_argument_group("log time window (mutually exclusive)")
    grp.add_argument(
        "--since", metavar="YYYY-MM-DD",
        help="Only scan logs on or after this date",
    )
    grp.add_argument(
        "--days", type=int, metavar="N",
        help="Only scan logs from the last N days",
    )

    parser.add_argument(
        "--max-pages", type=int, default=0,
        help="Max log pages to scan (20 entries/page, 0 = all available)",
    )
    parser.add_argument(
        "--scan-secrets", action="store_true",
        help=(
            "Scan secrets in configs the user accessed and list any high-entropy "
            "values (likely API keys / tokens) that should be manually rotated."
        ),
    )
    parser.add_argument(
        "--entropy-threshold", type=float, default=DEFAULT_ENTROPY_THRESHOLD,
        metavar="BITS",
        help=(
            f"Shannon entropy threshold (bits/char) for flagging secrets "
            f"(default: {DEFAULT_ENTROPY_THRESHOLD}). "
            "Random hex ≈ 4.0, base64 ≈ 6.0, alphanumeric ≈ 5.95"
        ),
    )
    parser.add_argument(
        "--min-secret-length", type=int, default=DEFAULT_MIN_SECRET_LENGTH,
        metavar="N",
        help=f"Minimum secret value length for entropy scan (default: {DEFAULT_MIN_SECRET_LENGTH})",
    )
    parser.add_argument(
        "--dump-unparsed", action="store_true",
        help="Print raw JSON for any lease log entries that couldn't be parsed",
    )

    args = parser.parse_args()

    # ── Validate env + args ──────────────────────────────────────────────────
    token = os.environ.get("DOPPLER_TOKEN")
    if not token:
        err("DOPPLER_TOKEN is not set.")
        err("Generate one at: https://dashboard.doppler.com/workplace/settings/tokens")
        sys.exit(1)

    if args.since and args.days:
        err("--since and --days are mutually exclusive.")
        sys.exit(1)

    since_dt = None
    if args.since:
        try:
            since_dt = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            err(f"Invalid --since date '{args.since}'. Use YYYY-MM-DD.")
            sys.exit(1)
    elif args.days:
        since_dt = datetime.now(timezone.utc) - timedelta(days=args.days)

    if not shutil.which("aws"):
        err("aws CLI not found in PATH. Install it and configure credentials.")
        sys.exit(1)

    dry_run = not args.delete

    # ── Banner ───────────────────────────────────────────────────────────────
    print()
    bold("  Doppler User Offboarder")
    print(f"  {'─' * 44}")
    log(f"User           : {C.BOLD}{args.user}{C.RESET}")
    log(f"Mode           : "
        + ("DRY RUN — no changes will be made"
           if dry_run else
           f"{C.RED}{C.BOLD}LIVE — credentials will be revoked/deleted{C.RESET}"))
    log(f"Prod handling  : "
        + ("skip"                       if args.skip_prod  else
           "force-delete (no prompt)"   if args.force_prod else
           "prompt per credential"))
    if since_dt:
        log(f"Log window     : since {since_dt.strftime('%Y-%m-%d')}")
    else:
        log(f"Log pages      : {args.max_pages if args.max_pages else 'all available'}")
    log(f"Secret scan    : "
        + (f"enabled  (entropy >= {args.entropy_threshold} bits/char, "
           f"min length {args.min_secret_length})"
           if args.scan_secrets else
           "disabled  (--scan-secrets to list secrets needing rotation)"))
    print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 1 — Scan activity logs
    # ══════════════════════════════════════════════════════════════════════════
    section("Phase 1 — Scanning activity logs")
    log("Fetching logs...")
    all_logs = fetch_all_logs(token, args.max_pages, since=since_dt)
    log(f"Total entries fetched       : {len(all_logs)}")

    user_logs = [
        e for e in all_logs
        if args.user.lower() in (extract_user_email(e) or "").lower()
    ]
    log(f"Entries for '{args.user}'   : {len(user_logs)}")

    lease_logs   = [e for e in user_logs if is_lease_event(e)]
    svc_tok_logs = [e for e in user_logs if is_service_token_event(e)]
    log(f"Dynamic lease events        : {len(lease_logs)}")
    log(f"Service token create events : {len(svc_tok_logs)}")
    print()

    if not user_logs:
        ok("No activity found for this user in the scanned log window.")
        if not since_dt:
            warn("Log retention varies by plan: Developer=3d, Team=90d, Enterprise=3yr.")
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 2 — Access report
    # ══════════════════════════════════════════════════════════════════════════
    section("Phase 2 — Projects & configs the user accessed")
    access_report = build_access_report(user_logs)

    if not access_report:
        dim("  No project/config access records found.")
    else:
        sorted_items = sorted(
            access_report.items(),
            key=lambda x: x[1]["last_seen"] or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        prod_count = sum(1 for _, v in sorted_items if v["is_prod"])
        log(f"{len(sorted_items)} project/config pair(s)  ({prod_count} prod)")
        print()
        print(f"  {'PROJECT':<26} {'CONFIG':<22} {'ENV':<12} {'LAST SEEN':<22} EVENTS")
        print(f"  {'─'*26} {'─'*22} {'─'*12} {'─'*22} {'─'*6}")
        for (project, config), meta in sorted_items:
            env     = meta["environment"]
            is_prod = meta["is_prod"]
            last    = format_dt(meta["last_seen"])
            count   = meta["event_count"]
            # Print without ANSI inside width specifiers to avoid alignment issues
            print(f"  {project:<26} {config:<22} ", end="")
            if is_prod:
                print(f"{C.RED}{env.upper():<12}{C.RESET} ", end="")
            else:
                print(f"{env.upper():<12} ", end="")
            print(f"{last:<22} {count}")
    print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 3 — Service tokens
    # ══════════════════════════════════════════════════════════════════════════
    section("Phase 3 — Service tokens created by user")

    svc_tok_events = [parse_service_token_event(e) for e in svc_tok_logs]

    # Group events by (project, config)
    svc_configs = {}
    for evt in svc_tok_events:
        key = (evt["project"], evt["config"])
        if key not in svc_configs:
            svc_configs[key] = {**evt, "events": []}
        svc_configs[key]["events"].append(evt)

    st_revoked = 0
    st_skipped = 0
    st_failed  = 0

    if not svc_configs:
        dim("  No service token creation events found in the scanned log window.")
        dim("  Tokens created before the log retention window won't appear here.")
        print()
    else:
        warn(f"  Found creation events across {len(svc_configs)} config(s).")
        warn("  The activity log cannot confirm whether a token was later revoked.")
        warn("  Tokens below are configs where this user created service tokens.")
        print()

        for (project, config), meta in svc_configs.items():
            is_prod    = meta["is_prod"]
            env        = meta["environment"]
            env_colour = C.RED if is_prod else C.CYAN
            events     = meta["events"]

            print(f"  {env_colour}{C.BOLD}{'[PROD] ' if is_prod else ''}"
                  f"{project} / {config}{C.RESET}")
            if is_prod:
                print(f"  {C.RED}WARNING: This is a production config.")
                print(f"  Revoking service tokens may break applications actively using them.{C.RESET}")

            # Show what the log captured
            for evt in events:
                name_hint = f"  '{evt['token_name']}'" if evt["token_name"] else ""
                age, _    = lease_age_str(evt["created_at"])
                print(f"    Log: created{name_hint} on {evt['created_at']}  ({age})")

            print()

            # Fetch current live tokens
            if args.skip_prod and is_prod:
                warn(f"    --skip-prod: skipping {project}/{config}.")
                st_skipped += 1
                print()
                continue

            current_tokens = fetch_service_tokens(token, project, config)
            if current_tokens is None:
                warn(f"    No permission to list tokens for {project}/{config} — skipping.")
                print()
                continue
            if not current_tokens:
                dim(f"    No active service tokens currently exist in {project}/{config}.")
                print()
                continue

            # Names seen in the logs help hint which token(s) the user created
            created_names = {
                evt["token_name"] for evt in events if evt["token_name"]
            }

            print(f"    Active tokens ({len(current_tokens)}):")
            for tok in current_tokens:
                tok_name    = tok.get("name", "unnamed")
                tok_slug    = tok.get("slug", "")
                tok_created = tok.get("created_at", "unknown")
                tok_access  = tok.get("access", "read")
                user_flag   = (f"  {C.GREEN}← user created this{C.RESET}"
                               if tok_name in created_names else "")
                print(f"      • {C.BOLD}{tok_name}{C.RESET}  "
                      f"slug={tok_slug[:12]}...  "
                      f"created={tok_created}  "
                      f"access={tok_access}"
                      f"{user_flag}")
            print()

            # Revocation prompts
            for tok in current_tokens:
                tok_name = tok.get("name", "unnamed")
                tok_slug = tok.get("slug", "")
                user_flag = (f"{C.GREEN}(user created){C.RESET} "
                             if tok_name in created_names else "")

                if dry_run:
                    dim(f"    [dry-run] Would prompt: revoke '{tok_name}'? {user_flag}")
                    continue

                do_revoke = False
                if args.force_prod:
                    warn(f"    --force-prod: revoking '{tok_name}'.")
                    do_revoke = True
                else:
                    try:
                        do_revoke = prompt_yn(
                            f"Revoke service token {C.BOLD}'{tok_name}'{C.RESET} "
                            f"in {project}/{config}? {user_flag}"
                        )
                    except KeyboardInterrupt:
                        warn("  Aborted.")
                        st_skipped += len(current_tokens)
                        break

                if do_revoke:
                    if revoke_service_token(token, project, config, tok_slug, dry_run=False):
                        ok(f"    Revoked '{tok_name}'.")
                        st_revoked += 1
                    else:
                        st_failed += 1
                else:
                    warn(f"    Skipped '{tok_name}'.")
                    st_skipped += 1
            print()

        if not dry_run:
            log(f"Service tokens — revoked: {st_revoked}  "
                f"skipped: {st_skipped}  failed: {st_failed}")
    print()

    # ── Parse lease events ───────────────────────────────────────────────────
    leases   = []
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

    log(f"IAM users to process: {len(leases)} total  "
        f"({len(non_prod_leases)} non-prod, {C.RED}{len(prod_leases)} prod{C.RESET})")
    print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 4 — Non-production dynamic IAM users
    # ══════════════════════════════════════════════════════════════════════════
    section(f"Phase 4 — Non-production dynamic IAM users ({len(non_prod_leases)})")

    np_deleted = 0
    np_failed  = 0

    if not non_prod_leases:
        dim("  None found.")
    else:
        for i, lease in enumerate(non_prod_leases, 1):
            print_lease(lease, i, len(non_prod_leases))
            success = delete_iam_user(lease["aws_username"], dry_run)
            if success:
                if not dry_run:
                    ok("    Deleted.")
                np_deleted += 1
            else:
                np_failed += 1
    print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 5 — Production dynamic IAM users
    # ══════════════════════════════════════════════════════════════════════════
    section(f"Phase 5 — Production dynamic IAM users ({len(prod_leases)})")

    p_deleted = 0
    p_failed  = 0
    p_skipped = 0

    if not prod_leases:
        dim("  None found.")
    elif args.skip_prod:
        warn(f"  --skip-prod: skipping all {len(prod_leases)} prod credential(s).")
        p_skipped = len(prod_leases)
    else:
        if not dry_run:
            print()
            print(f"  {C.RED}{C.BOLD}WARNING — production credentials detected{C.RESET}")
            print(f"  {C.RED}Deletion immediately revokes access to production AWS resources.{C.RESET}")

        for i, lease in enumerate(prod_leases, 1):
            print_lease(lease, i, len(prod_leases))
            print()

            if dry_run:
                dim(f"  [dry-run] Would prompt: delete {lease['aws_username']}? (y/n)")
                p_deleted += 1
                continue

            if args.force_prod:
                warn("  --force-prod: auto-confirming.")
                do_delete = True
            else:
                _, expired = lease_age_str(lease["created_at"])
                expiry_note = (
                    "Lease TTL has expired but IAM user may still exist in AWS"
                    if expired else
                    f"{C.YELLOW}Lease may still be ACTIVE — "
                    f"deletion immediately revokes prod access{C.RESET}"
                )
                print(f"  {C.RED}{C.BOLD}PROD — {lease['project']} / {lease['config']}{C.RESET}")
                print(f"  {expiry_note}")
                try:
                    do_delete = prompt_yn(
                        f"Delete {C.BOLD}{lease['aws_username']}{C.RESET}?"
                    )
                except KeyboardInterrupt:
                    print()
                    warn("  Aborted.")
                    p_skipped += len(prod_leases) - (i - 1)
                    break

            if do_delete:
                if delete_iam_user(lease["aws_username"], dry_run=False):
                    ok("    Deleted.")
                    p_deleted += 1
                else:
                    p_failed += 1
            else:
                warn(f"  Skipped {lease['aws_username']}.")
                p_skipped += 1
    print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 6 — High-entropy secret scan
    # ══════════════════════════════════════════════════════════════════════════
    section("Phase 6 — Secrets requiring manual rotation")

    total_flagged = 0
    no_access_ct  = 0

    if not args.scan_secrets:
        dim("  Skipped. Use --scan-secrets to enable.")
        dim("  Fetches secrets from every config the user accessed and lists")
        dim("  any high-entropy values (likely API keys / tokens) that should")
        dim("  be manually rotated now that this user has been offboarded.")
        print()
    elif not access_report:
        dim("  No accessed configs to scan.")
        print()
    else:
        # Unique (project, config) pairs, sorted prod-first
        seen_configs = set()
        configs_to_scan = []
        for meta in sorted(access_report.values(),
                           key=lambda m: (not m["is_prod"], m["project"], m["config"])):
            p = meta["project"]
            c = meta["config"]
            if c and c != "unknown" and (p, c) not in seen_configs:
                seen_configs.add((p, c))
                configs_to_scan.append((p, c, meta["is_prod"]))

        log(f"Scanning {len(configs_to_scan)} config(s)  "
            f"(entropy >= {args.entropy_threshold} bits/char, "
            f"length >= {args.min_secret_length})")
        print()

        for project, config, is_prod in configs_to_scan:
            secrets = fetch_secrets(token, project, config)

            if secrets is None:
                dim(f"  {project}/{config} — no read access, skipping.")
                no_access_ct += 1
                continue

            if not secrets:
                continue

            flagged = {
                name: val for name, val in secrets.items()
                if (not name.startswith("DOPPLER_")
                    and is_high_entropy(val, args.entropy_threshold, args.min_secret_length))
            }

            if not flagged:
                continue

            total_flagged += len(flagged)
            env_colour = C.RED if is_prod else C.CYAN
            print(f"  {env_colour}{C.BOLD}{'[PROD] ' if is_prod else ''}"
                  f"{project} / {config}{C.RESET}")
            print(f"  {C.YELLOW}Rotate these secrets manually in the Doppler dashboard.{C.RESET}")
            print(f"  {C.YELLOW}Set a reminder on each so owners are notified.{C.RESET}")
            print()

            for name, val in sorted(flagged.items()):
                entropy = shannon_entropy(val)
                masked  = (val[:6] + "..." + val[-4:] if len(val) > 14 else "***")
                prod_tag = f" {C.RED}[PROD]{C.RESET}" if is_prod else ""
                print(f"    {C.BOLD}{name}{C.RESET}{prod_tag}")
                print(f"      Length  : {len(val)} chars")
                print(f"      Entropy : {entropy:.2f} bits/char")
                print(f"      Preview : {C.DIM}{masked}{C.RESET}")
                print()
            print()

        if no_access_ct:
            dim(f"  {no_access_ct} config(s) skipped — token lacks read access.")
        if total_flagged:
            print(f"  {C.YELLOW}{C.BOLD}Action required:{C.RESET} "
                  f"{total_flagged} secret(s) listed above should be rotated.")
            print(f"  {C.DIM}Dashboard: project → config → secret → clock icon → set reminder{C.RESET}")
        else:
            ok("  No high-entropy secrets found in accessible configs.")
        print()

    # ══════════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C.CYAN}{'═' * 60}{C.RESET}")
    bold("  Summary")
    print(f"  {'─' * 44}")
    print(f"  Log entries scanned          : {len(all_logs)}")
    print(f"  Log entries for user         : {len(user_logs)}")
    print(f"  Projects/configs accessed    : {len(access_report)}")
    print()
    print(f"  Service token events found   : {len(svc_tok_logs)}")
    if not dry_run:
        print(f"  Service tokens revoked       : {st_revoked}")
    print()
    print(f"  Dynamic IAM (non-prod) {'deleted' if not dry_run else 'found'} : {np_deleted}")
    if np_failed:
        print(f"  Non-prod failures            : {np_failed}")
    print()
    print(f"  Dynamic IAM (prod) {'deleted' if not dry_run else 'found'}     : {p_deleted}")
    if p_skipped:
        print(f"  Prod IAM skipped             : {p_skipped}  (re-run to handle)")
    if p_failed:
        print(f"  Prod failures                : {p_failed}")
    if args.scan_secrets:
        print()
        print(f"  Secrets flagged for rotation : {total_flagged}")
        if no_access_ct:
            print(f"  Configs with no read access  : {no_access_ct}")

    if dry_run:
        print()
        warn("Dry run complete — no changes were made.")
        warn("Re-run with --delete to apply revocations.")
    print()


if __name__ == "__main__":
    main()
