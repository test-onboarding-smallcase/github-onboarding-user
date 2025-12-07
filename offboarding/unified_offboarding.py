#!/usr/bin/env python3
"""
Unified (single-tool) GitHub offboard driver.

- Extract email from ClickUp task custom field 'Email' OR from the task name
  (handles "User Suspended - abcd@smallcase.com" etc).
- Derive GitHub username from configured audit mongo (env-driven) if not present.
- Import and call remove_user_from_org from offboarding/github_offboarding.py.
- Upsert audit entry using utils.upsert_audit_entry (keeps audit shape consistent).
"""
from __future__ import annotations
import os
import sys
import argparse
import logging
import re
import json
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)sZ [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
logging.Formatter.converter = time.gmtime

# put repo root / offboarding dir on sys.path so imports work
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# reuse utils
try:
    from utils.utils_module import get_clickup_info, get_secret, upsert_audit_entry, get_clickup_approvers_from_comments
except Exception as e:
    logging.exception("Failed importing utils.utils_module: %s", e)
    raise

# import only the function we need from the existing github_offboarding module
try:
    # module path: offboarding/github_offboarding.py
    from offboarding.github_offboarding import remove_user_from_org
except Exception:
    # fallback using importlib if package import fails
    from importlib.machinery import SourceFileLoader
    GITHUB_OFFBOARD_PATH = HERE / "github_offboarding.py"
    if not GITHUB_OFFBOARD_PATH.exists():
        logging.error("Cannot find github_offboarding.py at %s", GITHUB_OFFBOARD_PATH)
        raise SystemExit(1)
    github_mod = SourceFileLoader("github_offboarding_for_import", str(GITHUB_OFFBOARD_PATH)).load_module()
    remove_user_from_org = getattr(github_mod, "remove_user_from_org")

# mongodb usage
try:
    import pymongo
except Exception:
    logging.exception("pymongo required; install it in the runner")
    raise

CLICKUP_TASK_API_NAME_REGEX = re.compile(r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})')

def extract_email_from_task_name(task_name: str) -> str | None:
    if not task_name:
        return None
    m = CLICKUP_TASK_API_NAME_REGEX.search(task_name)
    if m:
        return m.group(1).lower()
    return None

def derive_github_from_audit_db(email: str) -> str | None:
    """
    Use env vars (GITHUB_AUDIT_MONGO_URI / GITHUB_AUDIT_DB / GITHUB_AUDIT_COLL)
    or fallback to MONGO_URI / MONGO_DB_NAME / MONGO_COLLECTION.
    Returns first candidate username found in fields: github, github_username, username, login.
    """
    uri = os.environ.get("GITHUB_AUDIT_MONGO_URI") or os.environ.get("MONGO_URI")
    db_name = os.environ.get("GITHUB_AUDIT_DB") or os.environ.get("MONGO_DB_NAME")
    coll_name = os.environ.get("GITHUB_AUDIT_COLL") or os.environ.get("MONGO_COLLECTION")

    if not (uri and db_name and coll_name):
        logging.info("GitHub audit DB env vars not present; skipping username derivation.")
        return None

    try:
        client = pymongo.MongoClient(uri)
        db = client.get_database(db_name)
        coll = db.get_collection(coll_name)
        logging.info("Querying audit collection %s.%s for email=%s", db_name, coll_name, email)
        doc = coll.find_one({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}})
        client.close()
        if not doc:
            logging.info("No audit document found for email=%s", email)
            return None
        for key in ("github", "github_username", "username", "login"):
            val = doc.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        # nested shapes
        user_obj = doc.get("user") or doc.get("actor") or {}
        if isinstance(user_obj, dict):
            for key in ("login", "username"):
                val = user_obj.get(key)
                if val:
                    return val
        logging.info("Audit document found but no username field in expected keys.")
        return None
    except Exception:
        logging.exception("Error querying audit DB")
        return None

def fetch_task_name_direct(task_id: str, clickup_token: str) -> str | None:
    """
    If utils.get_clickup_info doesn't expose the task name, fetch raw task via ClickUp API.
    We do a minimal GET to read the 'name' field.
    """
    import requests
    url = f"https://api.clickup.com/api/v2/task/{task_id}"
    headers = {"Authorization": clickup_token}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        j = resp.json()
        name = j.get("name")
        if name:
            return name
        # fallback: title might be in 'task_name' or similar
        for k in ("task_name", "title"):
            if j.get(k):
                return j.get(k)
        return None
    except Exception:
        logging.exception("Failed to fetch raw ClickUp task name")
        return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--clickup-task", required=True, help="ClickUp task id (contains email or custom field)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--infra-admin", required=False)
    args = p.parse_args()

    secrets = get_secret("vpn-butler-mongo-admin")
    clickup_token = os.environ.get("CLICKUP_API_TOKEN") or (secrets and secrets.get("CLICKUP_API_TOKEN"))
    clickup_team_id = os.environ.get("CLICKUP_TEAM_ID") or "603234"
    if not clickup_token:
        logging.error("CLICKUP_API_TOKEN unavailable")
        raise SystemExit(2)

    task_id = args.clickup_task.strip()
    logging.info("Fetching ClickUp info for %s", task_id)
    cu = get_clickup_info(task_id, clickup_token, clickup_team_id)
    if isinstance(cu, tuple) and cu[0] is False:
        logging.error("ClickUp fetch failed: %s", cu[1])
        raise SystemExit(3)
    if not isinstance(cu, dict):
        logging.error("Unexpected ClickUp response format")
        raise SystemExit(3)

    # prefer custom-field Email if present; else try to parse from task name
    email = cu.get("Email")
    if not email:
        # try to get name from the returned dict; some implementations provide it as 'name'
        name_candidate = cu.get("name")
        if not name_candidate:
            # fetch raw name from API
            name_candidate = fetch_task_name_direct(task_id, clickup_token)
        email = extract_email_from_task_name(name_candidate) if name_candidate else None

    if email:
        email = email.lower()
    logging.info("Resolved email=%r from ClickUp (via custom field or task name)", email)

    # If ClickUp has GitHub username in any possible field, try to pick it
    github_username = cu.get("GitHub")
    if not github_username:
        # also check the 'GitHub' key could be inside custom_fields parsed differently
        github_username = cu.get("github") or cu.get("github_username")
    logging.info("ClickUp returned github field=%r", github_username)

    # If missing username, derive from audit DB (requires email)
    derived = False
    if not github_username:
        if not email:
            logging.error("No email available to derive GitHub username from audit DB. Aborting.")
            raise SystemExit(4)
        github_username = derive_github_from_audit_db(email)
        if github_username:
            derived = True
            logging.info("Derived github username=%s from audit DB", github_username)
        else:
            logging.error("Unable to derive github username for email=%s. Aborting.", email)
            raise SystemExit(5)

    # call remove_user_from_org (imported from github_offboarding)
    org = os.environ.get("DEFAULT_ORG", "smallcase")
    token = os.environ.get("ORG_ADMIN_TOKEN")
    if not token and not args.dry_run:
        logging.error("ORG_ADMIN_TOKEN missing (and not dry-run). Aborting.")
        raise SystemExit(6)

    logging.info("Proceeding to remove user %s from org %s (dry_run=%s)", github_username, org, args.dry_run)
    if args.dry_run:
        result = {"ok": False, "status": "dry_run"}
    else:
        try:
            result = remove_user_from_org(org, github_username, token)
        except Exception:
            logging.exception("Exception calling remove_user_from_org")
            result = {"ok": False, "status": "exception"}

    # upsert audit entry using existing util
    audit_status = result.get("status", "offboard_failed")
    try:
        approvers = []
        try:
            approvers = get_clickup_approvers_from_comments(task_id, clickup_token, clickup_team_id)
        except Exception:
            logging.debug("Could not fetch approvers from comments")

        if args.dry_run:
            logging.info("Dry-run: skipping audit upsert for %s", github_username)
        else:
            upsert_audit_entry(
                username=github_username,
                email=email,
                invited_by=os.environ.get("INVITED_BY", os.environ.get("USER", "unified_github_offboard")),
                invite_status=audit_status,
                clickup_task_id=task_id,
                clickup_approved_by=approvers,
                mongo_uri=os.environ.get("MONGO_URI"),
                db_name=os.environ.get("MONGO_DB_NAME"),
                collection_name=os.environ.get("MONGO_COLLECTION") or os.environ.get("GITHUB_AUDIT_COLL") or "offboarded_users",
            )
    except Exception:
        logging.exception("Failed to write audit entry")

    summary = {"clickup_task": task_id, "email": email, "github": github_username, "derived": derived, "result": result}
    logging.info("Summary: %s", json.dumps(summary, indent=2, default=str))

    if not args.dry_run and not result.get("ok", False):
        logging.error("Offboard failed, exit non-zero")
        raise SystemExit(2)

    logging.info("Done.")
    sys.exit(0)

if __name__ == "__main__":
    main()