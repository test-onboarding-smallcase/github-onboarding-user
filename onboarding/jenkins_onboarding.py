#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
import json
import argparse
import logging
import requests
from datetime import datetime

HERE = os.path.abspath(os.path.dirname(__file__))         
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))    
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import certifi
from pymongo import MongoClient

try:
    from utils.utils_module import get_clickup_info, get_clickup_approvers_from_comments, verify_email
except Exception as e:
    raise ImportError("Failed to import utils.utils_module.") from e

LOG = logging.getLogger("jenkins_onboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def get_crumb(session: requests.Session, base_url: str) -> dict:
    r = session.get(f"{base_url}/crumbIssuer/api/json", timeout=30)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    data = r.json()
    return {data["crumbRequestField"]: data["crumb"]}

def build_groovy(
                 user_perms: list[str],
                 groups: list[str],
                 group_perms: list[str],
                 sso_sid: str | None = None,
                 force_replace: bool = False) -> str:
    lines = []
    
    for p in user_perms:
        lines.append(f'grant("{p}", SID)')
    for g in groups:
        for p in group_perms:
            lines.append(f'grant("{p}", "{g}")')
    lines_block = "\n".join(lines)


    groovy_tpl = '''
import jenkins.model.Jenkins
import hudson.security.*
import groovy.json.JsonOutput
import groovy.transform.Field

def j = Jenkins.get()
def out = [] as List

// Inputs
def SID = __SID__

// Ensure Global Matrix strategy
def currStrategy = j.getAuthorizationStrategy()
out << "current_strategy:" + currStrategy.getClass().getName()
def strategy = null
if (!(currStrategy instanceof GlobalMatrixAuthorizationStrategy)) {
  out << "current_strategy_is_not_GlobalMatrixAuthorizationStrategy"
  if (!__FORCE_REPLACE__) {
    out << "refusing_to_replace_strategy_without_force_flag"
    def map = [:].withDefault { [] }
    def result = [events: out, matrix: map]
    return JsonOutput.toJson(result)
  } else {
    strategy = new GlobalMatrixAuthorizationStrategy()
    out << "replaced_with_new_GlobalMatrixAuthorizationStrategy"
  }
} else {
  strategy = currStrategy
  out << "using_existing_global_matrix_strategy"
}

// Snapshot pre-change
def preMatrix = [:].withDefault { [] }
def granted = j.getAuthorizationStrategy().getGrantedPermissions()
if (granted != null) {
  granted.each { perm, sids ->
    sids.each { sid ->
      preMatrix[sid] << perm.id
    }
  }
} else {
  out << "warning: getGrantedPermissions returned null"
}

// Permission map
@Field Map<String,Object> PERM = [
  "Overall/Administer": jenkins.model.Jenkins.ADMINISTER,
  "Overall/Read" : jenkins.model.Jenkins.READ,
  "Job/Build" : hudson.model.Item.BUILD,
  "Job/Cancel" : hudson.model.Item.CANCEL,
  "Job/Configure" : hudson.model.Item.CONFIGURE,
  "Job/Create" : hudson.model.Item.CREATE,
  "Job/Read" : hudson.model.Item.READ,
  "Job/Discover" : hudson.model.Item.DISCOVER,
  "Job/Workspace" : hudson.model.Item.WORKSPACE,
  "View/Read" : hudson.model.View.READ
]

// Grant helper
def grant = { String label, String sid ->
  if (label == null || sid == null) {
    out << "skip_invalid_grant(label=" + label + ", sid=" + sid + ")"
    return
  }
  def p = PERM[label]
  if (p == null) {
    out << "unknown_perm_label:" + label
    return
  }
  try {
    strategy.add(p, sid)
    out << "granted:" + label + "->" + sid
  } catch (Throwable t) {
    out << "grant_failed:" + label + "->" + sid + ":" + t.toString()
  }
}

// Execute grants
__LINES_BLOCK__

// Persist
if (strategy == null) {
  out << "error: strategy_not_set; aborting_persist"
  def result = [events: out, pre_matrix: preMatrix, post_matrix: [:].withDefault { [] }]
  return JsonOutput.toJson(result)
}
j.setAuthorizationStrategy(strategy)
j.save()
out << "saved_strategy"

// Snapshot post-change
def map = [:].withDefault { [] }
strategy.getGrantedPermissions().each { perm, sids ->
  sids.each { sid ->
    map[sid] << perm.id
  }
}

out << "final_perms_for_user:" + (map[SID] ? map[SID].join(",") : "")
out << "matrix_snapshot_count:" + map.size()

// JSON result
def result = [events: out, pre_matrix: preMatrix, post_matrix: map]
return JsonOutput.toJson(result)
'''.lstrip()

    groovy = (groovy_tpl
              .replace("__SID__", json.dumps(sso_sid or ""))
              .replace("__LINES_BLOCK__", lines_block)
              .replace("__FORCE_REPLACE__", "true" if force_replace else "false")
              )

    LOG.info("Built Groovy for SID=%s; preview length=%d", sso_sid, len(groovy))

    return groovy


def upsert_audit_entry_mongo(email: str,
                             invited_by: str | None,
                             invite_status: str,
                             clickup_task_id: str | None,
                             clickup_approved_by: str | None,
                             mongo_uri: str | None = None,
                             db_name: str | None = None,
                             collection_name: str | None = None) -> bool:
    try:
        uri = mongo_uri or os.environ.get("MONGO_URI")
        if not uri:
            LOG.error("MONGO_URI not provided; audit upsert skipped.")
            return False
        
        if not email:
            LOG.error("upsert_audit_entry_mongo requires a non-empty email")
            return False
        


        db_name = db_name or os.environ.get("MONGO_DB_NAME") or "Jenkins"
        coll_name = collection_name or os.environ.get("MONGO_COLLECTION") or "active_users"

        client = MongoClient(uri, serverSelectionTimeoutMS=15000, tls=True, tlsCAFile=certifi.where())
        client.server_info()

        db = client[db_name]
        coll = db[coll_name]

        try:
            coll.create_index([("email", 1)], unique=True, partialFilterExpression={"email": {"$exists": True}})
        except Exception:
            pass

        now = datetime.utcnow()
        onboarded_at = now if invite_status in ("invited", "accepted", "member_existing") else None

        doc = {
            "email": email,
            "invited_by": invited_by or os.environ.get("INVITED_BY", "jenkins_onboard_script"),
            "invite_status": invite_status,
            "clickup_task_id": clickup_task_id,
            "clickup_approved_by": clickup_approved_by,
            "onboarded_at": onboarded_at,
            "updated_at": now,
            "offboarding_status": False,
        }

        query = {"email": email}
        coll.update_one(query, {"$set": doc}, upsert=True)
        client.close()
        LOG.info("Upserted audit entry for email=%s clickup_task=%s", email, clickup_task_id)
        return True
    except Exception as e:
        LOG.exception("Failed to upsert audit entry: %s", e)
        return False


def parse_args():
    p = argparse.ArgumentParser(description="Jenkins onboarding with ClickUp -> Jenkins -> audit DB.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--clickup-task", help="ClickUp task id to fetch Email")
    group.add_argument("--email", help="Direct email (local testing)")
    p.add_argument("--groups", default="", help="Comma-separated SIDs (default empty)")
    p.add_argument("--user-perms", default=(
        "Overall/Read,"
        "Job/Build,Job/Cancel,Job/Configure,Job/Create,Job/Read,Job/Workspace,"
        "View/Read"
    ), help="Comma-separated user perms")
    p.add_argument("--group-perms", default="Overall/Read,Job/Discover,View/Read", help="Comma-separated group perms")
    p.add_argument("--jenkins-url", default=os.environ.get("JENKINS_URL", "http://localhost:8080"))
    p.add_argument("--user", default=os.environ.get("JENKINS_USER"))
    p.add_argument("--token", default=os.environ.get("JENKINS_TOKEN"))
    p.add_argument("--dry-run", action="store_true", help="Preview Groovy, no Jenkins POST")
    p.add_argument("--force-replace-strategy", action="store_true", help="DANGEROUS: Replace strategy")
    return p.parse_args()


def main():
    args = parse_args()

    # Fetch from ClickUp or use --email
    email = None
    clickup_task = None
    combined_approvers = []

    if args.clickup_task:
        clickup_task = args.clickup_task
        api_token = os.environ.get("CLICKUP_API_TOKEN", "").strip()
        team_id = os.environ.get("CLICKUP_TEAM_ID", "").strip()
        if not api_token or not team_id:
            LOG.error("CLICKUP_API_TOKEN and CLICKUP_TEAM_ID required")
            sys.exit(2)

        LOG.info("Fetching ClickUp task %s", clickup_task)
        cu = get_clickup_info(clickup_task, api_token, team_id)
        if not cu or (isinstance(cu, tuple) and cu[0] is False):
            LOG.error("Failed to fetch ClickUp: %s", cu)
            sys.exit(3)

        email = cu.get("Email") or cu.get("email")
        try:
            comment_approvers = get_clickup_approvers_from_comments(clickup_task, api_token, team_id)
        except Exception:
            comment_approvers = []
        combined_approvers = []
        for a in (cu.get("Approver") or []) + (comment_approvers or []):
            if a and a not in combined_approvers:
                combined_approvers.append(a)

        LOG.info("ClickUp: Email=%s Approvers=%s", email, combined_approvers)
    else:
        email = args.email.strip()

    
    if not email:
        LOG.error("No email. Ensure ClickUp has Email or provide --email.")
        sys.exit(4)

    email = email.lower().strip()
    # Validate the email format/domain using utils_module.verify_email
    if not verify_email(email):
        LOG.error("Resolved email %r is not allowed by verify_email(); aborting.", email)
        sys.exit(4)

    sso_sid = email

    # Parse perms/groups
    def _parse_csv(s): return [p.strip() for p in s.split(",") if p.strip()]
    def _dedupe(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    user_perms = _dedupe(_parse_csv(args.user_perms))
    groups = _dedupe(_parse_csv(args.groups))
    group_perms = _dedupe(_parse_csv(args.group_perms))

    if not sso_sid:
        LOG.error("No SSO SID available (sso_sid empty); aborting.")
        sys.exit(5)

    # Build Groovy
    groovy = build_groovy(
        user_perms=user_perms,
        groups=groups,
        group_perms=group_perms,
        force_replace=args.force_replace_strategy,
        sso_sid=sso_sid,
    )

    # Dry-run
    if args.dry_run:
        print(json.dumps({
            "action": "dry-run",
            "groovy_preview": groovy[:4096]
        }, indent=2))
        sys.exit(0)

    # Jenkins execution
    if not args.user or not args.token:
        LOG.error("JENKINS_USER and JENKINS_TOKEN required")
        sys.exit(2)

    try:
        with requests.Session() as s:
            s.auth = (args.user, args.token)
            headers = get_crumb(s, args.jenkins_url)
            r = s.post(f"{args.jenkins_url.rstrip('/')}/scriptText", data={"script": groovy}, headers=headers, timeout=60)
            r.raise_for_status()
            raw_text = r.text or ""
            LOG.info("Jenkins execution success; response length=%d", len(raw_text))
    except requests.RequestException as e:
        LOG.error("Jenkins failed: status=%s, exception=%s",
                  getattr(e.response, "status_code", None),
                  str(e))
        invite_status = "failed"
        # build a safe error blob (no tokens)
        result_blob = {
            "error": "jenkins_request_failed",
            "status_code": getattr(e.response, "status_code", None),
            "response_excerpt": (getattr(e.response, "text", None) or "")[:2000],
            "exception": str(e)
        }
        # Do not print whole response; exit after upsert attempt below
        result_text_parsed = result_blob
    else:
        # Attempt to robustly parse Jenkins output (Groovy returns a JSON object but Jenkins may prefix with text)
        json_start = raw_text.find("{")
        json_payload = raw_text[json_start:] if json_start != -1 else raw_text
        try:
            jres = json.loads(json_payload)
        except Exception:
            LOG.warning("Failed to parse Jenkins JSON; falling back to line events")
            # fallback: collect non-empty lines as 'events'
            lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
            jres = {"events": lines, "post_matrix": {}}

        # normalize matrix name variants used across templates
        matrix = jres.get("post_matrix") or jres.get("matrix") or jres.get("postMatrix") or {}
        events = jres.get("events") or []

        # pick the principal key used to report final perms: SSO vs local username
        principal_key = sso_sid
        final_perms_for_user = matrix.get(principal_key) or []

        # determine invite status from events (created_user => invited; else member_existing)
        invite_status = "member_existing"
        for ev in events:
            if isinstance(ev, str) and ev.startswith("granted:"):
                # if any grant was applied to the SID, treat as an 'invited' onboarding action
                invite_status = "invited"
                break

        # Build a reduced result for logs / output (safe to print)
        result_text_parsed = {
            "events": events,
            "final_perms_for_user": final_perms_for_user
        }

    # Upsert audit (use invite_status computed above)
    invited_by = os.environ.get("INVITED_BY", os.environ.get("USER", "jenkins_onboard_script"))
    clickup_last_approver = combined_approvers[-1] if combined_approvers else None

    audit_ok = upsert_audit_entry_mongo(
        email=email,
        invited_by=invited_by,
        invite_status=invite_status,
        clickup_task_id=clickup_task,
        clickup_approved_by=clickup_last_approver,
    )

    # Build output: include only safe, small items
    out = {
        "email": email,
        "auth": "SSO",
        "user_perms": user_perms,
        "groups": groups,
        "group_perms": group_perms,
        "clickup_task": clickup_task,
        "audit_upserted": bool(audit_ok),
        "jenkins_result": result_text_parsed,   # small, safe subset only
    }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()