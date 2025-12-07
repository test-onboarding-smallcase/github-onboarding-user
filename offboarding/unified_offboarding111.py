"""
Unified offboarding dispatcher.

Usage:
  python unified_offboard.py --clickup-task <id> [--infra-admin <name>] [--dry-run]

What it does:
- Fetches ClickUp task to get user email and GitHub username.
- Scans known audit collections in the infra audit Mongo for entries for that email/github.
- Decides which systems the user has access to (github, atlas, mongo, vpn).
- Calls existing module functions to offboard from each system, logging each step.
- Supports --dry-run.
"""

from __future__ import annotations
import os
import sys
import argparse
import logging
import json
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logging.Formatter.converter = time.gmtime

# Repo paths & helper loader
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent  # sc-infra-vpn-butler
SYS_PATH_INSERTED = False
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
    SYS_PATH_INSERTED = True

def load_module_from_path(name: str, path: Path):
    """Load a module by file path (works even if filename isn't a valid import name)."""
    logging.debug("Loading module %s from %s", name, path)
    return SourceFileLoader(name, str(path)).load_module()

try:
    from utils.utils_module import get_clickup_info, get_secret
except Exception as e:
    logging.exception("Failed to import utils.utils_module: %s", e)
    raise

# Load existing offboarding modules by path
# Map expected filenames to module names
MODULE_PATHS = {
    "github": HERE / "github_offboarding.py",
    "atlas": HERE / "atlas-off.py",           
    "mongo": HERE / "offboard-mongo.py",
    "vpn":   HERE / "offboard-vpn.py",
}

loaded = {}
for key, p in MODULE_PATHS.items():
    if p.exists():
        try:
            loaded[key] = load_module_from_path(f"offboard_{key}", p)
            logging.info("Loaded %s module from %s", key, p.name)
        except Exception:
            logging.exception("Failed to load module %s from %s", key, p)
    else:
        logging.warning("Expected module file %s not found; %s actions will be unavailable", p, key)


def scan_audit_db_for_user(email: str | None, github: str | None, secrets: dict) -> dict:
    """
    Scans audit DBs using email (preferred). Optionally tries a configurable
    GitHub-audit collection for deriving github username if not provided.
    Returns detected groups and raw matches.
    """
    import pymongo
    results = {"github": bool(github), "atlas": [], "mongo": [], "vpn": [], "raw_matches": {}}

    if not email:
        logging.error("scan_audit_db_for_user called without email - nothing to scan.")
        return results

    atlas_audit_user = secrets.get("ATLAS_AUDIT_DB_USER")
    atlas_audit_pass = secrets.get("ATLAS_AUDIT_DB_PASS")
    if not atlas_audit_user or not atlas_audit_pass:
        logging.error("Missing atlas audit DB creds in secrets; scanning aborted.")
        return results

    audit_host = "sc-infra-db-pl-2.uvjss.mongodb.net"
    mongo_uri = f"mongodb+srv://{atlas_audit_user}:{atlas_audit_pass}@{audit_host}/"
    client = pymongo.MongoClient(mongo_uri)

    try:
        q = {"email": email}

        # 1) Atlas prod rota
        try:
            db = client.get_database("smallcase_atlas")
            coll = db.get_collection("atlas_rota_prod_db_users")
            matches = list(coll.find(q))
            if matches:
                logging.info("Found %d atlas rota matches (AT-PROD)", len(matches))
                results["raw_matches"]["atlas_prod"] = matches
                results["atlas"].append("AT-PROD")
        except Exception:
            logging.debug("atlas_prod not present or unreadable; skipping", exc_info=True)

        # 2) smallcase_infra -> active_db_users (SC-PROD)
        try:
            db = client.get_database("smallcase_infra")
            coll = db.get_collection("active_db_users")
            matches = list(coll.find(q))
            if matches:
                results["raw_matches"]["mongo_smallcase_infra"] = matches
                results["mongo"].append("SC-PROD")
                logging.info("Found %d mongo matches in smallcase_infra.active_db_users", len(matches))
        except Exception:
            logging.debug("smallcase_infra.active_db_users missing or unreadable", exc_info=True)

        # 3) las_infra / unity_infra / nexum_infra
        for db_name, tag in [("las_infra", "LAS-PROD"), ("unity_infra", "UNITY-PROD"), ("nexum_infra", "NEXUM-PROD")]:
            try:
                db = client.get_database(db_name)
                coll = db.get_collection("active_db_users")
                if coll.count_documents(q) > 0:
                    results["raw_matches"][db_name] = list(coll.find(q))
                    results["mongo"].append(tag)
                    logging.info("Found mongo matches in %s.active_db_users", db_name)
            except Exception:
                pass

        # 4) VPN active_vpns in smallcase_infra
        try:
            db = client.get_database("smallcase_infra")
            coll = db.get_collection("active_vpns")
            matches = list(coll.find(q))
            if matches:
                results["raw_matches"]["vpn_smallcase_infra"] = matches
                for m in matches:
                    grp = m.get("prod_vpn_group") or "SC-PROD"
                    if grp not in results["vpn"]:
                        results["vpn"].append(grp)
                logging.info("Found %d vpn matches in smallcase_infra.active_vpns", len(matches))
        except Exception:
            logging.debug("No active_vpns in smallcase_infra or unreadable", exc_info=True)

        # 5) VPN in las_infra
        try:
            db = client.get_database("las_infra")
            coll = db.get_collection("active_vpns")
            if coll.count_documents(q) > 0:
                matches = list(coll.find(q))
                results["raw_matches"]["vpn_las_infra"] = matches
                for m in matches:
                    grp = m.get("prod_vpn_group") or "LAS-PROD"
                    if grp not in results["vpn"]:
                        results["vpn"].append(grp)
                logging.info("Found vpn matches in las_infra.active_vpns")
        except Exception:
            pass

        # 6) To set environment vars: GITHUB_AUDIT_MONGO_URI, GITHUB_AUDIT_DB, GITHUB_AUDIT_COLL
        github_audit_uri = os.environ.get("GITHUB_AUDIT_MONGO_URI")
        github_audit_db = os.environ.get("GITHUB_AUDIT_DB")
        github_audit_coll = os.environ.get("GITHUB_AUDIT_COLL")
        if github_audit_uri and github_audit_db and github_audit_coll:
            try:
                gclient = pymongo.MongoClient(github_audit_uri)
                gdb = gclient.get_database(github_audit_db)
                gcoll = gdb.get_collection(github_audit_coll)
                gmatch = gcoll.find_one({"email": email})
                if gmatch:
                    # expect gmatch to have a 'github' or 'github_username' field
                    derived = gmatch.get("github") or gmatch.get("github_username") or gmatch.get("username")
                    if derived:
                        logging.info("Derived github username from github-audit collection: %s", derived)
                        results["github"] = True
                        results.setdefault("raw_matches", {}).setdefault("github_audit", []).append(gmatch)
                        # attach the derived username so caller can use it
                        results.setdefault("derived", {})["github"] = derived
                gclient.close()
            except Exception:
                logging.exception("Failed to query GitHub audit DB; skipping github derivation")

    finally:
        client.close()

    logging.info("Scan complete. Detected: %s", json.dumps({k: results[k] for k in ("github", "atlas", "mongo", "vpn")}, default=str))
    return results

# Runner helper functions that call existing modules
def call_github_offboard(github_username: str, dry_run: bool):
    mod = loaded.get("github")
    if not mod:
        logging.warning("Github offboard module not loaded; skipping github.")
        return {"ok": False, "reason": "module-missing"}

    org = os.environ.get("DEFAULT_ORG", "smallcase")
    token = os.environ.get("ORG_ADMIN_TOKEN")
    if not token and not dry_run:
        logging.error("ORG_ADMIN_TOKEN not set in environment and not dry-run; cannot remove from GitHub org.")
        return {"ok": False, "reason": "missing-token"}

    logging.info("GitHub offboard: org=%s user=%s dry_run=%s", org, github_username, dry_run)
    if dry_run:
        logging.info("[dry-run] would call remove_user_from_org")
        return {"ok": True, "status": "dry_run"}
    try:
        return mod.remove_user_from_org(org, github_username, token)
    except Exception:
        logging.exception("Failed calling github.remove_user_from_org")
        return {"ok": False, "reason": "exception"}

def call_atlas_offboard(db_group: str, email: str, dry_run: bool, infra_admin: str | None, secrets: dict):
    mod = loaded.get("atlas")
    if not mod:
        logging.warning("Atlas offboard module not loaded; skipping atlas.")
        return False
    logging.info("Atlas offboard: db_group=%s email=%s dry_run=%s", db_group, email, dry_run)
    # atlas module has remove_expired_users(db_group, secrets, config)
    cfg = {
        "team_id": "603234",
        "clickup_api_token": secrets.get("CLICKUP_API_TOKEN"),
        "gh_action": "unified_dispatch",
        "gh_action_url": "",
        "user_email": email,
        "infra_admin": infra_admin
    }
    if dry_run:
        logging.info("[dry-run] atlas.remove_expired_users would be called for %s", db_group)
        return True
    try:
        return bool(mod.remove_expired_users(db_group, secrets, cfg))
    except Exception:
        logging.exception("Atlas offboard call failed for %s", db_group)
        return False

def call_mongo_offboard(db_group: str, email: str, dry_run: bool, infra_admin: str | None, secrets: dict):
    mod = loaded.get("mongo")
    if not mod:
        logging.warning("Mongo offboard module not loaded; skipping mongo.")
        return False
    logging.info("Mongo offboard: db_group=%s email=%s dry_run=%s", db_group, email, dry_run)
    cfg = {
        "team_id": "603234",
        "clickup_api_token": secrets.get("CLICKUP_API_TOKEN"),
        "gh_action": "unified_dispatch",
        "gh_action_url": "",
        "user_email": email,
        "infra_admin": infra_admin
    }
    if dry_run:
        logging.info("[dry-run] mongo.remove_expired_users would be called for %s", db_group)
        return True
    try:
        return bool(mod.remove_expired_users(db_group, secrets, cfg))
    except Exception:
        logging.exception("Mongo offboard call failed for %s", db_group)
        return False

def call_vpn_offboard(vpn_group: str, email: str, dry_run: bool, infra_admin: str | None, secrets: dict):
    mod = loaded.get("vpn")
    if not mod:
        logging.warning("VPN offboard module not loaded; skipping vpn.")
        return False
    logging.info("VPN offboard: vpn_group=%s email=%s dry_run=%s", vpn_group, email, dry_run)

    # Build config similar to existing offboard-vpn.py's configs
    configs = {
        "SC-PROD": {
            "db": {"user": secrets.get("ATLAS_AUDIT_DB_USER"), "password": secrets.get("ATLAS_AUDIT_DB_PASS"), "host": "sc-infra-db-pl-2.uvjss.mongodb.net", "name": "smallcase_infra"},
            "pritunl": {"base_url": "https://pritunl.smallcase.com", "api_token": secrets.get("PRITUNL_SC_API_TOKEN"), "api_secret": secrets.get("PRITUNL_SC_API_SECRET"), "org_id": secrets.get("PRITUNL_SC_ORG")}
        },
        "LAS-PROD": {
            "db": {"user": secrets.get("ATLAS_AUDIT_DB_USER"), "password": secrets.get("ATLAS_AUDIT_DB_PASS"), "host": "sc-infra-db.uvjss.mongodb.net", "name": "las_infra"},
            "pritunl": {"base_url": "https://pritunl-prod.las.smallcase.com", "api_token": secrets.get("PRITUNL_LAS_API_TOKEN"), "api_secret": secrets.get("PRITUNL_LAS_API_SECRET"), "org_id": secrets.get("PRITUNL_LAS_ORG")}
        }
    }

    cfg = configs.get(vpn_group)
    if not cfg:
        logging.warning("Unknown vpn_group %s - skipping", vpn_group)
        return False

    cfg.update({
        "google_credentials": get_secret("google-credentials-vpn-butler"),
        "clickup_api_token": secrets.get("CLICKUP_API_TOKEN"),
        "team_id": "603234",
        "gh_action": "unified_dispatch",
        "gh_action_url": "",
        "user_email": email,
        "infra_admin": infra_admin
    })
    cfg["user_email"] = email

    if dry_run:
        logging.info("[dry-run] vpn.remove_expired_vpns would be called for %s", vpn_group)
        return True
    try:
        return bool(mod.remove_expired_vpns(cfg))
    except Exception:
        logging.exception("VPN offboard call failed for %s", vpn_group)
        return False

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--clickup-task", required=True, help="ClickUp task id (contains email/github)")
    p.add_argument("--infra-admin", required=False, help="Name/email of infra admin initiating the run")
    p.add_argument("--dry-run", action="store_true", help="Don't perform destructive actions (safe)")
    args = p.parse_args()

    logging.info("Unified offboard started for ClickUp task %s", args.clickup_task)

    # Get ClickUp info (requires CLICKUP_API_TOKEN or fallback via get_secret)
    secrets = get_secret("vpn-butler-mongo-admin")
    clickup_token = os.environ.get("CLICKUP_API_TOKEN") or secrets.get("CLICKUP_API_TOKEN")
    team_id = os.environ.get("CLICKUP_TEAM_ID") or "603234"
    if not clickup_token:
        logging.error("CLICKUP_API_TOKEN missing in env and secrets; cannot fetch ClickUp task. Aborting.")
        sys.exit(2)

    cu = get_clickup_info(args.clickup_task, clickup_token, team_id)
    if isinstance(cu, tuple) and cu[0] is False:
        logging.error("Failed getting ClickUp info: %s", cu[1])
        sys.exit(3)
    if not isinstance(cu, dict):
        logging.error("Unexpected ClickUp response format")
        sys.exit(3)

    email = cu.get("Email")
    github = cu.get("GitHub")

    if not email and not github:
        logging.error("ClickUp task missing both Email and GitHub fields; cannot proceed")
        sys.exit(4)

    logging.info("ClickUp returned email=%r github=%r", email, github)

    # Scan audit DB(s) to see where the user has access
    scan = scan_audit_db_for_user(email, github, secrets)
    derived_github_used = False
    if not github:
        derived = scan.get("derived", {}).get("github")
        if derived:
            logging.info("GitHub username not in ClickUp ticket; using derived username from audit DB: %s", derived)
            github = derived
            derived_github_used = True
        else:
            logging.info("No GitHub username available from ClickUp or audit derivation; GitHub offboard will be skipped unless provided.")

    summary = {
        "clickup_task": args.clickup_task,
        "email": email,
        "github": github,
        "scan": scan,
        "actions": {},
    }
    if derived_github_used:
        summary.setdefault("scan", {})["derived_github_used"] = True

    # 1) Github
    if github:
        logging.info("Starting GitHub offboard for %s", github)
        gh_res = call_github_offboard(github, args.dry_run)
        summary["actions"]["github"] = gh_res
    else:
        logging.info("No github id provided; skipping GitHub offboard")
        summary["actions"]["github"] = {"skipped": True}

    # 2) Atlas offboards (all detected atlas groups)
    atlas_groups = scan.get("atlas", [])
    summary["actions"]["atlas"] = {}
    for g in atlas_groups:
        ok = call_atlas_offboard(g, email, args.dry_run, args.infra_admin, secrets)
        summary["actions"]["atlas"][g] = ok

    # 3) Mongo offboards (all detected mongo groups)
    mongo_groups = scan.get("mongo", [])
    summary["actions"]["mongo"] = {}
    for g in mongo_groups:
        ok = call_mongo_offboard(g, email, args.dry_run, args.infra_admin, secrets)
        summary["actions"]["mongo"][g] = ok

    # 4) VPN offboards (all detected vpn groups)
    vpn_groups = scan.get("vpn", [])
    summary["actions"]["vpn"] = {}
    for g in vpn_groups:
        ok = call_vpn_offboard(g, email, args.dry_run, args.infra_admin, secrets)
        summary["actions"]["vpn"][g] = ok

    logging.info("Unified offboard finished. Summary:\n%s", json.dumps(summary, indent=2, default=str))

    # exit code: 0 if all true/dry-run; 2 if any false
    any_fail = False
    for svc in ("github", "atlas", "mongo", "vpn"):
        v = summary["actions"].get(svc)
        if isinstance(v, dict):
            for k, val in v.items():
                if val is False or (isinstance(val, dict) and not val.get("ok", True)):
                    any_fail = True
        elif v is False:
            any_fail = True

    if any_fail:
        logging.error("One or more offboard actions failed. Check logs above.")
        sys.exit(2)

    logging.info("All offboarding actions succeeded (or dry-run).")
    sys.exit(0)

if __name__ == "__main__":
    main()