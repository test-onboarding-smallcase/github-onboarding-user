from __future__ import annotations
import os
import sys
import argparse
import json
import logging
from typing import Optional, Tuple
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.utils_module import get_token, request_with_retries, die, get_clickup_info, verify_email, upsert_github_audit_entry, get_clickup_approvers_from_comments

# Logging setup 
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("onboard_user")


# Allow overriding log level via env (DEBUG, INFO, WARNING, ERROR)
if os.environ.get("ONBOARD_LOG_LEVEL"):
    level = os.environ.get("ONBOARD_LOG_LEVEL").upper()
    logger.setLevel(getattr(logging, level, logging.INFO))


# GitHub API flow functions
def ensure_user_exists(username: str, token: str) -> dict:
    logger.info("Looking up GitHub user '%s'...", username)
    resp = request_with_retries("GET", f"/users/{username}", token)
    if resp.status_code == 200:
        logger.info("User '%s' found (id=%s).", username, resp.json().get("id"))
        return resp.json()
    if resp.status_code == 404:
        die(f"GitHub user '{username}' not found (404). Check spelling or existence.", code=4)
    # other failure
    die(f"Failed to lookup user '{username}': {resp.status_code} {resp.text}", code=5)


def check_org_membership(org: str, username: str, token: str) -> Optional[dict]:
    logger.info("Checking membership for user '%s' in org '%s'...", username, org)
    resp = request_with_retries("GET", f"/orgs/{org}/memberships/{username}", token)
    if resp.status_code == 200:
        logger.info("Membership record exists for %s (state=%s).", username, resp.json().get("state"))
        return resp.json()
    if resp.status_code == 404:
        logger.info("No membership record found for %s in org %s (404).", username, org)
        return None
    if resp.status_code == 403:
        msg = resp.text or resp.reason
        logger.error("403 when checking membership: %s", msg)
        die("Permission denied when checking org membership. Token may be missing 'admin:org' or require SSO authorization.", code=6)
    die(f"Unexpected error checking membership: {resp.status_code} {resp.text}", code=7)


def invite_to_org(org: str, userid: int, role: Optional[str], token: str) -> dict:
    logger.info("Inviting user id=%s to org '%s' with role='%s'...", userid, org, role)
    payload = {"invitee_id": int(userid)}
    if role:
        payload["role"] = role
    resp = request_with_retries("POST", f"/orgs/{org}/invitations", token, json_payload=payload)
    # 201: created, 202: accepted/in progress depending; other statuses possible
    if resp.status_code in (201, 202):
        logger.info("Invitation created: status=%d", resp.status_code)
        try:
            return resp.json()
        except Exception:
            return {"status_code": resp.status_code, "body": resp.text}
    # 422 may mean existing invite or membership; return content for logging
    logger.warning("Invite endpoint returned status %d: %s", resp.status_code, resp.text)
    try:
        return resp.json()
    except Exception:
        return {"status_code": resp.status_code, "body": resp.text}


def add_user_to_team(org: str, team_slug: str, username: str, token: str, role: str = "member") -> Tuple[int, str]:
    logger.info("Setting membership for user '%s' on team '%s' in org '%s' (role=%s)...", username, team_slug, org, role)
    payload = {"role": role}
    resp = request_with_retries("PUT", f"/orgs/{org}/teams/{team_slug}/memberships/{username}", token, json_payload=payload)
    status = resp.status_code
    if status in (200, 201):
        try:
            state = resp.json().get("state")
            logger.info("Team membership API returned %d (state=%s)", status, state)
            return status, f"state={state}"
        except Exception:
            logger.info("Team membership API returned %d", status)
            return status, "ok"
    if status == 404:
        logger.error("Team '%s' not found or insufficient permissions (404)", team_slug)
        return status, "not_found"
    # Other failure
    logger.error("Failed to set team membership: %d -> %s", status, resp.text)
    return status, resp.text


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--org", required=False, help="Org slug (optional; defaults to DEFAULT_ORG env var or 'smallcase')")
    # p.add_argument("--username", required=False, help="GitHub username to onboard (optional if using --clickup-task)")
    p.add_argument("--teams", default="", help="Comma-separated team slugs (e.g., core-infra,infra-intern)")
    p.add_argument("--role", default="direct_member", choices=["direct_member", "admin"], help="Org role for the invite")
    p.add_argument("--clickup-task", required=False, help="ClickUp task id to pull Email and Github Username from the form")
    return p.parse_args()


def main():
    args = parse_args()
    # determine org: CLI > env DEFAULT_ORG > hardcoded 'smallcase'
    DEFAULT_ORG = os.environ.get("DEFAULT_ORG", "smallcase")
    org = args.org or DEFAULT_ORG

    # 1) If clickup-task supplied, fetch form data (email + github) first
    clickup_email = None
    clickup_github = None
    combined_approvers = []
    if args.clickup_task:
        logger.info("Fetching GitHub username, Email, and Approvers automatically from ClickUp task.")

        # strip whitespace/newlines from secrets (fixes team_id being sent as "%0A...")
        clickup_api_token = os.environ.get("CLICKUP_API_TOKEN", "").strip()
        clickup_team_id = os.environ.get("CLICKUP_TEAM_ID", "").strip()

        if not clickup_api_token or not clickup_team_id:
            die("CLICKUP_API_TOKEN and CLICKUP_TEAM_ID must be set when using --clickup-task", code=8)
        
        logger.info(f"Using ClickUp team ID: '{clickup_team_id}'")

        logger.info("Fetching ClickUp data for task %s...", args.clickup_task)
        cu = get_clickup_info(args.clickup_task, clickup_api_token, clickup_team_id)

        if not cu or (isinstance(cu, tuple) and cu[0] is False):
            logger.error("Failed to fetch ClickUp task or parse fields: %s", cu)
            die("ClickUp lookup failed", code=9)

        clickup_email = cu.get("Email")
        clickup_github = cu.get("GitHub")
        clickup_field_approvers = cu.get("Approver") or []

        try:
            clickup_comment_approvers = get_clickup_approvers_from_comments(
                args.clickup_task, clickup_api_token, clickup_team_id
            )
        except Exception:
            clickup_comment_approvers = []

        combined_approvers = []
        for a in (clickup_field_approvers or []) + (clickup_comment_approvers or []):
            if a and a not in combined_approvers:
                combined_approvers.append(a)

        logger.info("ClickUp returned GitHub username=%s email=%s approvers=%s",
                    clickup_github, clickup_email, combined_approvers)

    # Resolve username: CLI flag wins if provided; otherwise fallback to ClickUp
    username = clickup_github #or args.username
    if not username:
        # die("Missing GitHub username: provide --username or use --clickup-task with 'Github Username' field", code=3)
        die("Failed to extract GitHub username from ClickUp task. Ensure the ClickUp form has a 'GitHub Username' field.", code=3)

    token = get_token()

    logger.info("Starting onboarding run: org=%s username=%s teams=%s role=%s", org, username, args.teams, args.role)
    # 1) user exists
    user = ensure_user_exists(username, token)
    userid = user.get("id")
    logger.debug("Resolved userid=%s", userid)

    # choose email for audit: prefer ClickUp provided verified email, else try GitHub profile email
    email = clickup_email
    if email:
        if not verify_email(email):
            logger.warning("ClickUp email '%s' failed verify_email() check — ignoring it.", email)
            email = None
    if not email:
        email = user.get("email")  # GitHub profile email (may be None)

    if email:
        logger.info("Using email=%s for audit", email)
    else:
        logger.info("No email determined from ClickUp or GitHub profile.")

    # 2) check org membership
    membership = check_org_membership(org, username, token)
    if membership:
        state = membership.get("state", "<unknown>")
        role_existing = membership.get("role", "<unknown>")
        logger.info("User already has membership record: state=%s role=%s", state, role_existing)
        audit_status = "member_existing"
    else:
        logger.info("User not active in org. Creating invitation...")
        invite_resp = invite_to_org(org, userid, args.role, token)
        logger.info("Invite response: %s", json.dumps(invite_resp) if isinstance(invite_resp, dict) else str(invite_resp))
        # determine invite_status for audit: check known response shapes
        if isinstance(invite_resp, dict) and ("status" in invite_resp or "id" in invite_resp or "created_at" in invite_resp):
            audit_status = "invited"
        else:
            # fallback: if invite endpoint returned 201/202 the helper likely returned dict earlier
            audit_status = "invite_attempted"

    # 3) team assignments (kept manual as requested)
    teams = [t.strip() for t in args.teams.split(",") if t.strip()]
    if not teams:
        logger.info("No teams specified — skipping team assignment.")
    else:
        logger.info("Assigning to teams: %s", teams)
        for team in teams:
            status, info = add_user_to_team(org, team, username, token, role="member")
            if status in (200, 201):
                logger.info("Added/updated team membership: team=%s result=%s", team, info)
            elif status == 404:
                logger.error("Team not found or permission error for team=%s", team)
            else:
                logger.error("Failed to add to team=%s -> status=%s info=%s", team, status, info)

    # 4) final membership check
    logger.info("Performing final membership check (may still be pending until user accepts)...")
    final = check_org_membership(org, username, token)
    logger.info("Final membership record: %s", json.dumps(final, indent=2) if final else "No membership record found")

    # 5) write audit entry to infra DB (Mongo)
    try:
        invited_by = os.environ.get("INVITED_BY", os.environ.get("USER", "onboard_script"))
        clickup_last_approver = combined_approvers[-1] if combined_approvers else None
        upsert_ok = upsert_github_audit_entry(
            github_id=userid,
            username=username,
            email=email,
            invited_by=invited_by,
            invite_status=audit_status,
            clickup_task_id=args.clickup_task,
            clickup_approved_by=clickup_last_approver,
        )
        if not upsert_ok:
            logger.warning("Audit DB upsert failed for github_id=%s", userid)
    except Exception as e:
        logger.exception("Exception while writing audit entry: %s", e)

    logger.info("Onboarding run complete. If invitation is pending, user must accept it for membership to become active.")


if __name__ == "__main__":
    main()