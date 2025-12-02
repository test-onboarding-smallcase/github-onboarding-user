#!/usr/bin/env python3
"""
Dispatcher that imports existing offboarding modules and runs the appropriate functions
based on inputs. It attempts to call programmatic entrypoints (preferred) and falls
back to invoking module.main() by adjusting sys.argv so you don't have to refactor
all scripts immediately.

Usage (examples):
  python offboarding/dispatcher.py --tools github --clickup-task CU-123 --dry-run
  python offboarding/dispatcher.py --tools github,atlas,mongo,vpn --user-email user@example.com --db_group AT-PROD

Produces: offboarding_summary.json at repo root.
"""

from __future__ import annotations
import argparse
import importlib
import json
import os
import sys
import traceback
from datetime import datetime
from types import ModuleType
from typing import Any, Dict

# ensure repo root and offboarding package are importable
HERE = os.path.dirname(os.path.abspath(__file__))                 # .../offboarding
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))            # repo root
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# utilities for secrets (fallback)
try:
    from utils.utils_module import get_secret as utils_get_secret
except Exception:
    utils_get_secret = None  # ok if not available; modules may provide their own get_secret

SUMMARY_PATH = os.path.join(REPO_ROOT, "offboarding_summary.json")

def now_h() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def import_module_safe(module_path: str) -> ModuleType | None:
    try:
        return importlib.import_module(module_path)
    except Exception as e:
        print(f"[{now_h()}] Failed importing {module_path}: {e}")
        return None

def call_entrypoint_or_main(module: ModuleType, fallback_argv: list[str], call_spec: Dict[str, Any]):
    """
    Try in order:
    1) If module exposes a preferred programmatic function, call it with call_spec kwargs.
       - github: try run_github_offboard(clickup_task=..., org=..., dry_run=..., env=...)
       - atlas/mongo: try remove_expired_users(db_group, secrets, config)
       - vpn: try remove_expired_vpns(config)
    2) Else, call module.main() after setting sys.argv to fallback_argv.
    Returns dict describing the result.
    """
    try:
        # Github module: prefer run_github_offboard or run_offboard
        if module.__name__.endswith("github_offboarding"):
            if hasattr(module, "run_github_offboard"):
                print(f"[{now_h()}] Calling {module.__name__}.run_github_offboard()")
                res = module.run_github_offboard(
                    clickup_task=call_spec.get("clickup_task"),
                    org=call_spec.get("org"),
                    dry_run=call_spec.get("dry_run", False),
                    env=call_spec.get("env"),
                )
                return {"ok": bool(res and (res.get("ok", True) if isinstance(res, dict) else True)), "result": res}
            # fallback to main() via argv
        # Atlas / Mongo modules: prefer remove_expired_users(db_group, secrets, config)
        if module.__name__.endswith("atlas-off") or module.__name__.endswith("offboard-mongo") or module.__name__.endswith("atlas_off"):
            if hasattr(module, "remove_expired_users"):
                print(f"[{now_h()}] Calling {module.__name__}.remove_expired_users()")
                secrets = None
                if hasattr(module, "get_secret"):
                    try:
                        secrets = module.get_secret("vpn-butler-mongo-admin")
                    except Exception:
                        secrets = None
                if secrets is None and utils_get_secret:
                    try:
                        secrets = utils_get_secret("vpn-butler-mongo-admin")
                    except Exception:
                        secrets = None
                if secrets is None:
                    print(f"[{now_h()}] Warning: could not fetch secrets for {module.__name__}; proceeding with empty dict")
                    secrets = {}
                config = {
                    "team_id": "603234",
                    "clickup_api_token": call_spec.get("clickup_api_token") or (secrets.get("CLICKUP_API_TOKEN") if isinstance(secrets, dict) else None),
                    "gh_action": call_spec.get("gh_action") or "NIL",
                    "gh_action_url": call_spec.get("gh_action_url") or ("<https://github.com/smallcase/sc-infra-vpn-butler/actions/runs/{0}|{0}>".format(call_spec.get("gh_action"))),
                    "user_email": call_spec.get("user_email"),
                    "infra_admin": call_spec.get("infra_admin"),
                }
                # call with (db_group, secrets, config)
                res = module.remove_expired_users(call_spec.get("db_group"), secrets, config)
                return {"ok": bool(res), "result": res}
        # VPN module: prefer remove_expired_vpns(config)
        if module.__name__.endswith("offboard-vpn") or module.__name__.endswith("offboard_vpn") or module.__name__.endswith("offboard_vpn"):
            if hasattr(module, "remove_expired_vpns"):
                print(f"[{now_h()}] Calling {module.__name__}.remove_expired_vpns()")
                # fetch secrets same as above
                secrets = None
                if hasattr(module, "get_secret"):
                    try:
                        secrets = module.get_secret("vpn-butler-mongo-admin")
                    except Exception:
                        secrets = None
                if secrets is None and utils_get_secret:
                    try:
                        secrets = utils_get_secret("vpn-butler-mongo-admin")
                    except Exception:
                        secrets = None
                if secrets is None:
                    print(f"[{now_h()}] Warning: could not fetch secrets for {module.__name__}; proceeding with empty dict")
                    secrets = {}
                # build configs mapping similar to module's __main__ expectation
                configs = {
                    "SC-PROD": {
                        "db": {
                            "user": secrets.get("ATLAS_AUDIT_DB_USER"),
                            "password": secrets.get("ATLAS_AUDIT_DB_PASS"),
                            "host": 'sc-infra-db-pl-2.uvjss.mongodb.net',
                            "name": 'smallcase_infra'
                        },
                        "pritunl": {
                            "base_url": "https://pritunl.smallcase.com",
                            "api_token": secrets.get('PRITUNL_SC_API_TOKEN'),
                            "api_secret": secrets.get('PRITUNL_SC_API_SECRET'),
                            "org_id": secrets.get('PRITUNL_SC_ORG')
                        }
                    },
                    "LAS-PROD": {
                        "db": {
                            "user": secrets.get("ATLAS_AUDIT_DB_USER"),
                            "password": secrets.get("ATLAS_AUDIT_DB_PASS"),
                            "host": "sc-infra-db.uvjss.mongodb.net",
                            "name": 'las_infra'
                        },
                        "pritunl": {
                            "base_url": "https://pritunl-prod.las.smallcase.com",
                            "api_token": secrets.get('PRITUNL_LAS_API_TOKEN'),
                            "api_secret": secrets.get('PRITUNL_LAS_API_SECRET'),
                            "org_id": secrets.get('PRITUNL_LAS_ORG')
                        }
                    }
                }
                vpn_group = call_spec.get("vpn_group")
                if vpn_group not in configs:
                    return {"ok": False, "error": f"vpn_group '{vpn_group}' not supported or missing"}
                cfg = configs[vpn_group]
                cfg.update({
                    'google_credentials': (secrets.get("google-credentials-vpn-butler") if isinstance(secrets, dict) else None),
                    'clickup_api_token': secrets.get('CLICKUP_API_TOKEN') if isinstance(secrets, dict) else None,
                    'team_id': "603234",
                    'gh_action': call_spec.get("gh_action") or 'NIL',
                    'gh_action_url': call_spec.get("gh_action_url") or ("<https://github.com/smallcase/sc-infra-vpn-butler/actions/runs/{0}|{0}>".format(call_spec.get("gh_action"))),
                    'user_email': call_spec.get("user_email"),
                    'infra_admin': call_spec.get("infra_admin")
                })
                res = module.remove_expired_vpns(cfg)
                return {"ok": bool(res), "result": res}

        # Fallback: call module.main() by setting argv
        if hasattr(module, "main"):
            print(f"[{now_h()}] Falling back to calling {module.__name__}.main() with argv: {fallback_argv}")
            old_argv = sys.argv[:]
            try:
                sys.argv = fallback_argv
                # call main() and treat non-exception as success
                result = module.main()
                return {"ok": True, "result": result}
            finally:
                sys.argv = old_argv

        return {"ok": False, "error": "no suitable entrypoint found"}
    except SystemExit as se:
        # scripts may call sys.exit(); capture code
        code = se.code if hasattr(se, "code") else None
        return {"ok": False if code not in (0, None) else True, "system_exit_code": code}
    except Exception as e:
        tb = traceback.format_exc()
        return {"ok": False, "error": str(e), "traceback": tb}

def build_fallback_argv_for_tool(tool: str, args: argparse.Namespace) -> list[str]:
    """Construct argv for calling module.main() if we fallback."""
    argv = []
    if tool == "github":
        argv = ["github_offboarding.py"]
        if args.clickup_task:
            argv += ["--clickup-task", args.clickup_task]
        if args.org:
            argv += ["--org", args.org]
        if args.dry_run:
            argv += ["--dry-run"]
    elif tool == "atlas":
        argv = ["atlas-off.py"]
        if args.db_group:
            argv += ["--db_group", args.db_group]
        if args.gh_action:
            argv += ["--gh_action", args.gh_action]
        if args.user_email:
            argv += ["--user_email", args.user_email]
        if args.infra_admin:
            argv += ["--infra_admin", args.infra_admin]
    elif tool == "mongo":
        argv = ["offboard-mongo.py"]
        if args.db_group:
            argv += ["--db_group", args.db_group]
        if args.gh_action:
            argv += ["--gh_action", args.gh_action]
        if args.user_email:
            argv += ["--user_email", args.user_email]
        if args.infra_admin:
            argv += ["--infra_admin", args.infra_admin]
    elif tool == "vpn":
        argv = ["offboard-vpn.py"]
        if args.vpn_group:
            argv += ["--vpn_group", args.vpn_group]
        if args.gh_action:
            argv += ["--gh_action", args.gh_action]
        if args.user_email:
            argv += ["--user_email", args.user_email]
        if args.infra_admin:
            argv += ["--infra_admin", args.infra_admin]
    else:
        argv = [f"{tool}.py"]
    return argv

def main():
    parser = argparse.ArgumentParser(description="Unified offboarding dispatcher (import-style, modular)")
    parser.add_argument("--tools", required=True, help="Comma-separated list: github,atlas,mongo,vpn or 'all'")
    parser.add_argument("--user-email", help="user email (for atlas/mongo/vpn)")
    parser.add_argument("--github-username", help="github username (not required if clickup-task has it)")
    parser.add_argument("--clickup-task", help="clickup task id (for github offboard)")
    parser.add_argument("--db_group", help="DB group (e.g. AT-PROD, SC-PROD, etc.)")
    parser.add_argument("--vpn_group", help="VPN group (SC-PROD|LAS-PROD)")
    parser.add_argument("--gh-action", help="GitHub Actions run id (used for messages/links)")
    parser.add_argument("--infra-admin", help="Infra admin name/email (optional)")
    parser.add_argument("--org", help="GitHub org slug override (optional)")
    parser.add_argument("--dry-run", action="store_true", help="do not make destructive changes")
    args = parser.parse_args()

    requested = [t.strip() for t in args.tools.split(",")]
    if "all" in requested:
        requested = ["github", "atlas", "mongo", "vpn"]

    # build a common call_spec that will be used by programmatic entrypoints
    call_spec = {
        "user_email": args.user_email,
        "github_username": args.github_username,
        "clickup_task": args.clickup_task,
        "db_group": args.db_group,
        "vpn_group": args.vpn_group,
        "gh_action": args.gh_action,
        "gh_action_url": f"<https://github.com/smallcase/sc-infra-vpn-butler/actions/runs/{args.gh_action}|{args.gh_action}>" if args.gh_action else None,
        "infra_admin": args.infra_admin,
        "org": args.org,
        "dry_run": args.dry_run,
        "env": {},  # optional env to pass to run_* functions if they accept it
    }

    summary: Dict[str, Any] = {"summary_time": now_h(), "results": {}}
    any_failed = False

    # mapping to module paths
    tool_module_map = {
        "github": "offboarding.github_offboarding",
        "atlas": "offboarding.atlas-off",
        "mongo": "offboarding.offboard-mongo",
        "vpn": "offboarding.offboard-vpn",
    }

    for tool in requested:
        result = {"timestamp": now_h()}
        module_path = tool_module_map.get(tool)
        if not module_path:
            result.update({"ok": False, "error": f"unknown tool '{tool}'"})
            summary["results"][tool] = result
            any_failed = True
            continue

        print(f"[{now_h()}] Processing tool: {tool} (module: {module_path})")
        module = import_module_safe(module_path)
        if module is None:
            result.update({"ok": False, "error": "import_failed"})
            summary["results"][tool] = result
            any_failed = True
            continue

        fallback_argv = build_fallback_argv_for_tool(tool, args)
        try:
            res = call_entrypoint_or_main(module, fallback_argv, call_spec)
            result.update(res if isinstance(res, dict) else {"ok": bool(res), "result": res})
            if not result.get("ok"):
                any_failed = True
        except Exception as e:
            tb = traceback.format_exc()
            result.update({"ok": False, "error": str(e), "traceback": tb})
            any_failed = True

        summary["results"][tool] = result

    # write summary
    with open(SUMMARY_PATH, "w") as fh:
        json.dump(summary, fh, indent=2)

    print(f"[{now_h()}] Offboarding summary written to {SUMMARY_PATH}")
    print(json.dumps(summary, indent=2))

    if any_failed:
        print(f"[{now_h()}] One or more offboarding steps failed.")
        sys.exit(2)
    else:
        print(f"[{now_h()}] All selected offboarding steps reported success.")
        sys.exit(0)

if __name__ == "__main__":
    main()