from __future__ import annotations
import os
import sys
import argparse
import logging
import json
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.utils_module import (
    get_token,
    request_with_retries,
    die,
    get_clickup_info,
    verify_email,
    upsert_github_audit_entry,
    get_clickup_approvers_from_comments,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logging.Formatter.converter = time.gmtime
logger = logging.getLogger("offboard_user")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--org", required=False, help="Org slug (defaults to DEFAULT_ORG or 'smallcase')")
    p.add_argument("--clickup-task", required=True, help="ClickUp task ID")
    return p.parse_args()


def remove_user_from_org(org: str, username: str, token: str) -> dict:
    """
    Remove a user from a GitHub org using REST DELETE.
    """
    logger.info("Checking membership before removal...")
    check_resp = request_with_retries("GET", f"/orgs/{org}/members/{username}", token)

    if check_resp.status_code == 404:
        logger.info("User %s is not a member of %s", username, org)
        return {"ok": False, "status": "not_member"}

    # DELETE /orgs/{org}/members/{username}
    logger.info("Removing user %s from org %s...", username, org)
    del_resp = request_with_retries("DELETE", f"/orgs/{org}/members/{username}", token)

    if del_resp.status_code in (204, 200):
        logger.info("User %s removed successfully.", username)
        return {"ok": True, "status": "removed"}

    logger.error("Failed to remove user: %s %s", del_resp.status_code, del_resp.text)
    return {"ok": False, "status": "failed", "details": del_resp.text}


def main():
    args = parse_args()

    DEFAULT_ORG = os.environ.get("DEFAULT_ORG", "smallcase")
    org = args.org or DEFAULT_ORG

    clickup_api_token = (os.environ.get("CLICKUP_API_TOKEN") or "").strip()
    clickup_team_id = (os.environ.get("CLICKUP_TEAM_ID") or "").strip()

    if not clickup_api_token or not clickup_team_id:
        die("CLICKUP_API_TOKEN and CLICKUP_TEAM_ID must be set", code=8)

    logger.info("Fetching ClickUp task details...")
    cu = get_clickup_info(args.clickup_task, clickup_api_token, clickup_team_id)

    # If ClickUp returned an error tuple (False, msg)
    if isinstance(cu, tuple) and cu[0] is False:
        logger.error("ClickUp lookup failed: %s", cu[1])
        die("ClickUp lookup failed", code=9)

    if not isinstance(cu, dict):
        die("Unexpected ClickUp response format", code=9)

    username = cu.get("GitHub")
    email = cu.get("Email")

    if not username:
        die("ClickUp task missing GitHub username", code=3)

    logger.info("ClickUp returned username=%s email=%s", username, email)

    # Collect approvers
    try:
        approvers = get_clickup_approvers_from_comments(
            args.clickup_task, clickup_api_token, clickup_team_id
        )
    except Exception:
        approvers = []

    logger.info("Approvers: %s", approvers)

    # Even if email fails verification, store raw in audit
    raw_email = email
    verified_email = email if (email and verify_email(email)) else None

    token = get_token()

    logger.info("Starting offboarding for %s", username)
    result = remove_user_from_org(org, username, token)

    audit_status = result.get("status", "offboard_failed")

    # Write audit entry (separate collection for offboarded users)
    try:
        invited_by = os.environ.get("INVITED_BY", os.environ.get("USER", "offboard_script"))

        upsert_github_audit_entry(
            github_id=0,               # offboarding does not need a GitHub ID
            username=username,
            email=raw_email,
            invited_by=invited_by,
            invite_status=audit_status,
            clickup_task_id=args.clickup_task,
            clickup_approved_by=approvers,
            collection_name="offboarded_users",
        )
    except Exception as e:
        logger.exception("Failed writing audit entry: %s", e)

    logger.info("Offboarding complete: %s", result)


if __name__ == "__main__":
    main()