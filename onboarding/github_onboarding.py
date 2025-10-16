from __future__ import annotations
import os
import sys
import argparse
import json
import logging
from typing import Optional, Tuple
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.utils_module import get_token, request_with_retries, die

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
    p.add_argument("--username", required=True, help="GitHub username to onboard")
    p.add_argument("--teams", default="", help="Comma-separated team slugs (e.g., core-infra,infra-intern)")
    p.add_argument("--role", default="direct_member", choices=["direct_member", "admin"], help="Org role for the invite")
    return p.parse_args()


def main():
    args = parse_args()
    # determine org: CLI > env DEFAULT_ORG > hardcoded 'smallcase'
    DEFAULT_ORG = os.environ.get("DEFAULT_ORG", "test-onboarding-smallcase")
    org = args.org or DEFAULT_ORG

    token = get_token()

    logger.info("Starting onboarding run: org=%s username=%s teams=%s role=%s", org, args.username, args.teams, args.role)
    # 1) user exists
    user = ensure_user_exists(args.username, token)
    userid = user.get("id")
    logger.debug("Resolved userid=%s", userid)

    # 2) check org membership
    membership = check_org_membership(org, args.username, token)
    if membership:
        state = membership.get("state", "<unknown>")
        role_existing = membership.get("role", "<unknown>")
        logger.info("User already has membership record: state=%s role=%s", state, role_existing)
    else:
        logger.info("User not active in org. Creating invitation...")
        invite_resp = invite_to_org(org, userid, args.role, token)
        logger.info("Invite response: %s", json.dumps(invite_resp) if isinstance(invite_resp, dict) else str(invite_resp))

    # 3) team assignments
    teams = [t.strip() for t in args.teams.split(",") if t.strip()]
    if not teams:
        logger.info("No teams specified — skipping team assignment.")
    else:
        logger.info("Assigning to teams: %s", teams)
        for team in teams:
            status, info = add_user_to_team(org, team, args.username, token, role="member")
            if status in (200, 201):
                logger.info("Added/updated team membership: team=%s result=%s", team, info)
            elif status == 404:
                logger.error("Team not found or permission error for team=%s", team)
            else:
                logger.error("Failed to add to team=%s -> status=%s info=%s", team, status, info)

    # 4) final membership check
    logger.info("Performing final membership check (may still be pending until user accepts)...")
    final = check_org_membership(org, args.username, token)
    logger.info("Final membership record: %s", json.dumps(final, indent=2) if final else "No membership record found")

    logger.info("Onboarding run complete. If invitation is pending, user must accept it for membership to become active.")


if __name__ == "__main__":
    main()