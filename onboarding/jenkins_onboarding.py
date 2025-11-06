#!/usr/bin/env python3
"""
Jenkins onboarding shim for testing ClickUp -> audit DB behaviour.

Usage (test):
  # Fetch email from ClickUp task, create local username/password, and upsert audit record.
  python onboarding/jenkins_onboarding.py --clickup-task 86d0w10pw

Usage (manual/test without ClickUp):
  python onboarding/jenkins_onboarding.py --email test.user@smallcase.com

Notes:
- This script intentionally comments out the live Jenkins HTTP/groovy execution.
- It will still generate the Groovy payload and will upsert a record into MongoDB:
  DB name: Jenkins
  Collection: active_users
- It imports helpers from utils.utils_module (get_clickup_info, get_clickup_approvers_from_comments).
"""

from __future__ import annotations
import os
import re
import sys
import json
import argparse
import secrets
import string
import logging
from datetime import datetime
HERE = os.path.abspath(os.path.dirname(__file__))          # .../repo/onboarding
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))      # .../repo
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
# mongo deps
import certifi
from pymongo import MongoClient

# local utils (assumes repository layout where utils/utils_module.py exists)
# The utils module contains get_clickup_info and get_clickup_approvers_from_comments
try:
    from utils.utils_module import get_clickup_info, get_clickup_approvers_from_comments
except Exception as e:
    # fall back with clear error for devs if import fails
    raise ImportError("Failed to import utils.utils_module. Ensure script runs from repo root and utils/utils_module.py is present.") from e

LOG = logging.getLogger("jenkins_onboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def username_from_email(email: str) -> str:
    local = email.split("@", 1)[0].lower()
    u = re.sub(r"[^a-z0-9]+", "_", local).strip("_")
    return u or "user"


def gen_password(n: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def build_groovy(username: str,
                 password: str,
                 email: str,
                 set_email: bool,
                 user_perms: list[str],
                 groups: list[str],
                 group_perms: list[str],
                 reset_password: bool) -> str:
    """
    Return Groovy script string. This is identical to your working script's builder.
    """
    lines = []
    for p in user_perms:
        lines.append(f'grant("{p}", "{username}")')
    for g in groups:
        for p in group_perms:
            lines.append(f'grant("{p}", "{g}")')
    lines_block = "\n".join(lines)

    email_block = """
// Set email if Mailer plugin is available
try {
  def cl = j.getPluginManager().uberClassLoader
  def MailerUserProp = cl.loadClass('hudson.tasks.Mailer$UserProperty')
  def current = u.getProperty(MailerUserProp)
  if (current == null || current.address != EMAIL) {
    u.addProperty(MailerUserProp.getConstructor(String).newInstance(EMAIL))
    u.save()
  }
} catch (Throwable ignore) {
  // Mailer not installed; skip setting email
}
""".strip() if set_email else "// Email setting skipped by flag"

    reset_block = """
// Reset password on existing user as requested
def details = hudson.security.HudsonPrivateSecurityRealm.Details.fromPlainPassword(PASSWORD)
u.addProperty(details)
u.save()
""".strip() if reset_password else "// Password reset skipped"

    # Use placeholder-free substitution to avoid Groovy interpolation surprises
    groovy_tpl = f'''
import jenkins.model.Jenkins
import hudson.security.*
import hudson.model.User
import groovy.json.JsonOutput
import groovy.transform.Field

def j = Jenkins.get()
def out = [] as List

// Ensure local user database
def realm = j.getSecurityRealm()
if (!(realm instanceof HudsonPrivateSecurityRealm)) {{
  throw new IllegalStateException("Local user database (HudsonPrivateSecurityRealm) required.")
}}

// Inputs
def USERNAME = "{username}"
def PASSWORD = "{password}"
def EMAIL    = "{email}"

// Create user if absent; otherwise optionally reset password
def u = User.get(USERNAME, false)
if (u == null) {{
  realm.createAccount(USERNAME, PASSWORD)
  u = User.get(USERNAME)
  out << "created_user:" + USERNAME
}} else {{
  out << "user_exists:" + USERNAME
  {reset_block}
  if ({str(reset_password).lower()}) {{
    out << "password_reset_done"
  }}
}}

{email_block}

// Ensure Global Matrix strategy
def strategy = j.getAuthorizationStrategy()
if (!(strategy instanceof GlobalMatrixAuthorizationStrategy)) {{
  strategy = new GlobalMatrixAuthorizationStrategy()
  out << "installed_new_global_matrix_strategy"
}} else {{
  out << "using_existing_global_matrix_strategy"
}}

// Label → Permission constants (Jenkins 2.289.x)
@Field Map<String,Object> PERM = [
  "Overall/Administer": jenkins.model.Jenkins.ADMINISTER,
  "Overall/Read"     : jenkins.model.Jenkins.READ,

  "Job/Build"        : hudson.model.Item.BUILD,
  "Job/Cancel"       : hudson.model.Item.CANCEL,
  "Job/Configure"    : hudson.model.Item.CONFIGURE,
  "Job/Create"       : hudson.model.Item.CREATE,
  "Job/Read"         : hudson.model.Item.READ,
  "Job/Discover"     : hudson.model.Item.DISCOVER,
  "Job/Workspace"    : hudson.model.Item.WORKSPACE,

  "View/Read"        : hudson.model.View.READ
]

// Helper: add a grant with per-call logging (closure so it captures `strategy`)
def grant = {{ String label, String sid ->
  if (label == null || sid == null) {{
    out << "skip_invalid_grant(label=" + label + ", sid=" + sid + ")"
    return
  }}
  def p = PERM[label]
  if (p == null) {{
    out << "unknown_perm_label:" + label
    return
  }}
  try {{
    strategy.add(p, sid)
    out << "granted:" + label + "->" + sid
  }} catch (Throwable t) {{
    out << "grant_failed:" + label + "->" + sid + ":" + t.toString()
  }}
}}

// Execute the requested grants
{lines_block}

// Persist and show results
j.setAuthorizationStrategy(strategy)
j.save()
out << "saved_strategy"

/*
 Build a map {{ sid: [ permission ids ] }} for final verification
*/
def map = [:].withDefault {{ [] }}
strategy.getGrantedPermissions().each {{ perm, sids ->
  sids.each {{ sid ->
    map[sid] << perm.id
  }}
}}

// Add the specific user's final permissions to output for easy consumption
def user_perms_final = map[USERNAME]
out << "final_perms_for_user:" + (user_perms_final ? user_perms_final.join(",") : "")
out << "matrix_snapshot_count:" + map.size()

// Return structured JSON so Python can parse it easily
def result = [events: out, matrix: map]
return JsonOutput.toJson(result)
'''.lstrip()

    return groovy_tpl


def upsert_audit_entry_mongo(username: str,
                             email: str | None,
                             invited_by: str | None,
                             invite_status: str,
                             clickup_task_id: str | None,
                             clickup_approved_by: str | None,
                             mongo_uri: str | None = None,
                             db_name: str | None = None,
                             collection_name: str | None = None) -> bool:
    """
    Upsert an audit record using username as a unique key.
    DB default: Jenkins
    Collection default: active_users
    """
    try:
        uri = mongo_uri or os.environ.get("MONGO_URI")
        if not uri:
            LOG.error("MONGO_URI not provided; audit upsert skipped.")
            return False

        db_name = db_name or os.environ.get("MONGO_DB_NAME") or "Jenkins"
        coll_name = collection_name or os.environ.get("MONGO_COLLECTION") or "active_users"

        client = MongoClient(uri, serverSelectionTimeoutMS=15000, tls=True, tlsCAFile=certifi.where())
        client.server_info()  # raises on failure

        db = client[db_name]
        coll = db[coll_name]

        # Ensure an index on username exists (idempotent)
        try:
            coll.create_index([("username", 1)], unique=True)
        except Exception:
            pass

        now = datetime.utcnow()
        onboarded_at = now if invite_status in ("invited", "accepted", "member_existing") else None

        doc = {
            "username": username,
            "email": email,
            "invited_by": invited_by or os.environ.get("INVITED_BY", "jenkins_onboard_script"),
            "invite_status": invite_status,
            "clickup_task_id": clickup_task_id,
            "clickup_approved_by": clickup_approved_by,
            "onboarded_at": onboarded_at,
            "updated_at": now,
            "offboarding_status": False,
        }

        coll.update_one({"username": username}, {"$set": doc}, upsert=True)
        client.close()
        LOG.info("Upserted audit entry for username=%s email=%s", username, email)
        return True
    except Exception as e:
        LOG.exception("Failed to upsert audit entry: %s", e)
        return False


def parse_args():
    p = argparse.ArgumentParser(description="Jenkins onboarding test harness. Uses ClickUp task to fetch email and writes audit to Mongo.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--clickup-task", help="ClickUp task id to fetch Email (preferred for CI)")
    group.add_argument("--email", help="Direct email to use (for local testing)")
    p.add_argument("--set-email", action="store_true", help="Set email on Jenkins user (skipped in this test harness)")
    p.add_argument("--reset-password", action="store_true", help="Reset password if user exists (simulated)")
    p.add_argument("--groups", default="authenticated", help="Comma-separated SIDs to grant (kept for groovy generation)")
    p.add_argument("--user-perms", default=(
        "Overall/Read,"
        "Job/Build,Job/Cancel,Job/Configure,Job/Create,Job/Read,Job/Workspace,"
        "View/Read"
    ), help="Comma-separated permission labels for the user")
    p.add_argument("--group-perms", default="Overall/Read,Job/Discover,View/Read", help="Comma-separated permission labels applied to each group SID")
    return p.parse_args()


def main():
    args = parse_args()

    # 1) Extract email either from ClickUp or use provided
    email = None
    clickup_task = None
    combined_approvers = []

    if args.clickup_task:
        clickup_task = args.clickup_task
        api_token = os.environ.get("CLICKUP_API_TOKEN", "").strip()
        team_id = os.environ.get("CLICKUP_TEAM_ID", "").strip()
        if not api_token or not team_id:
            LOG.error("CLICKUP_API_TOKEN and CLICKUP_TEAM_ID must be set as env vars to use --clickup-task")
            sys.exit(2)

        LOG.info("Fetching ClickUp task %s", clickup_task)
        cu = get_clickup_info(clickup_task, api_token, team_id)
        if not cu or (isinstance(cu, tuple) and cu[0] is False):
            LOG.error("Failed to fetch/parse ClickUp task: %s", cu)
            sys.exit(3)

        email = cu.get("Email")
        # fetch approver list from comments (same helper used in other onboard flows)
        try:
            comment_approvers = get_clickup_approvers_from_comments(clickup_task, api_token, team_id)
        except Exception:
            comment_approvers = []
        # combine field approvers + comment approvers
        combined_approvers = []
        for a in (cu.get("Approver") or []) + (comment_approvers or []):
            if a and a not in combined_approvers:
                combined_approvers.append(a)

        LOG.info("ClickUp resolved Email=%s Approvers=%s", email, combined_approvers)

    else:
        email = args.email.strip()

    if not email:
        LOG.error("No email could be determined. Ensure ClickUp task has an Email field or provide --email.")
        sys.exit(4)

    # Basic email normalization/validation
    email = email.lower().strip()
    username = username_from_email(email)
    password = gen_password(20)

    # Parse perms / groups
    def _parse_csv(s): return [p.strip() for p in s.split(",") if p.strip()]
    user_perms = _parse_csv(args.user_perms)
    groups = _parse_csv(args.groups)
    group_perms = _parse_csv(args.group_perms)

    # Build Groovy payload (kept for visibility / later use)
    groovy = build_groovy(username, password, email, args.set_email, user_perms, groups, group_perms, args.reset_password)

    # 2) --- SIMULATION: skip live Jenkins execution ---
    # The following block is intentionally commented out to avoid network calls to Jenkins
    #
    # with requests.Session() as s:
    #     s.auth = (JENKINS_USER, JENKINS_TOKEN)
    #     headers = get_crumb(s, JENKINS_URL) ...
    #     r = s.post(f"{JENKINS_URL}/scriptText", data={"script": groovy}, headers=headers)
    #     r.raise_for_status()
    #     result = r.text.strip()
    #
    # Instead, we simulate what a successful run would output and record events.

    simulated_events = [
        f"user_created_or_verified:{username}",
        "password_generated",
        "permissions_granted:" + ",".join(user_perms),
    ]
    simulated_matrix_snapshot = {
        "authenticated": ["hudson.model.Hudson.Read", "hudson.model.Item.Discover", "hudson.model.View.Read"],
        username: ["hudson.model.Hudson.Read"] + [f"hudson.model.Item.{p.split('/')[-1]}" for p in user_perms if p.startswith("Job/")]  # rough map
    }

    simulated_result = {
        "events": simulated_events,
        "matrix": simulated_matrix_snapshot
    }

    # 3) Upsert audit entry to MongoDB (Jenkins.active_users)
    invited_by = os.environ.get("INVITED_BY", os.environ.get("USER", "jenkins_onboard_script"))
    clickup_last_approver = combined_approvers[-1] if combined_approvers else None

    audit_ok = upsert_audit_entry_mongo(
        username=username,
        email=email,
        invited_by=invited_by,
        invite_status="invited",
        clickup_task_id=clickup_task,
        clickup_approved_by=clickup_last_approver,
        # DB/collection can be overridden via env MONGO_URI / MONGO_DB_NAME / MONGO_COLLECTION
    )

    out = {
        "username": username,
        "email": email,
        "password": password,
        "user_perms": user_perms,
        "groups": groups,
        "group_perms": group_perms,
        "reset_password": args.reset_password,
        "clickup_task": clickup_task,
        "audit_upserted": bool(audit_ok),
        "simulated_result": simulated_result,
        "groovy_preview": groovy[:4096]  # include a truncated preview for inspection
    }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()