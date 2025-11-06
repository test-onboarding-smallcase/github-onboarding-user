#!/usr/bin/env python3
import os, re, sys, json, argparse, secrets, string, requests
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.utils_module import (
    get_clickup_info,
    get_clickup_approvers_from_comments,
    upsert_github_audit_entry,
    verify_email
)
def username_from_email(email: str) -> str:
    local = email.split("@", 1)[0].lower()
    u = re.sub(r"[^a-z0-9]+", "_", local).strip("_")
    return u or "user"

def gen_password(n=20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

def get_crumb(session: requests.Session, base_url: str) -> dict:
    r = session.get(f"{base_url}/crumbIssuer/api/json", timeout=30)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    data = r.json()
    return {data["crumbRequestField"]: data["crumb"]}

def build_groovy(username: str,
                 password: str,
                 email: str,
                 set_email: bool,
                 user_perms: list[str],
                 groups: list[str],
                 group_perms: list[str],
                 reset_password: bool) -> str:

    # Build grant() calls for user and groups
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

    # Template uses placeholder tokens that we will replace with Python .replace()
    groovy_tpl = '''
import jenkins.model.Jenkins
import hudson.security.*
import hudson.model.User
import groovy.json.JsonOutput
import groovy.transform.Field

def j = Jenkins.get()
def out = [] as List

// Ensure local user database
def realm = j.getSecurityRealm()
if (!(realm instanceof HudsonPrivateSecurityRealm)) {
  throw new IllegalStateException("Local user database (HudsonPrivateSecurityRealm) required.")
}

// Inputs
def USERNAME = "__USERNAME__"
def PASSWORD = "__PASSWORD__"
def EMAIL    = "__EMAIL__"

// Create user if absent; otherwise optionally reset password
def u = User.get(USERNAME, false)
if (u == null) {
  realm.createAccount(USERNAME, PASSWORD)
  u = User.get(USERNAME)
  out << "created_user:" + USERNAME
} else {
  out << "user_exists:" + USERNAME
  __RESET_BLOCK__
  if (__RESET_FLAG__) {
    out << "password_reset_done"
  }
}

__EMAIL_BLOCK__

// Ensure Global Matrix strategy
def strategy = j.getAuthorizationStrategy()
if (!(strategy instanceof GlobalMatrixAuthorizationStrategy)) {
  strategy = new GlobalMatrixAuthorizationStrategy()
  out << "installed_new_global_matrix_strategy"
} else {
  out << "using_existing_global_matrix_strategy"
}

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

// Execute the requested grants
__LINES_BLOCK__

// Persist and show results
j.setAuthorizationStrategy(strategy)
j.save()
out << "saved_strategy"

/*
 Build a map {{ sid: [ permission ids ] }} for final verification
*/
def map = [:].withDefault { [] }
strategy.getGrantedPermissions().each { perm, sids ->
  sids.each { sid ->
    map[sid] << perm.id
  }
}

// Add the specific user's final permissions to output for easy consumption
def user_perms_final = map[USERNAME]
out << "final_perms_for_user:" + (user_perms_final ? user_perms_final.join(",") : "")
out << "matrix_snapshot_count:" + map.size()

// Return structured JSON so Python can parse it easily
def result = [events: out, matrix: map]
return JsonOutput.toJson(result)
'''.lstrip()

    # Perform safe replacements
    groovy = (groovy_tpl
              .replace("__USERNAME__", username)
              .replace("__PASSWORD__", password)
              .replace("__EMAIL__", email)
              .replace("__RESET_BLOCK__", reset_block)
              .replace("__EMAIL_BLOCK__", email_block)
              .replace("__LINES_BLOCK__", lines_block)
              .replace("__RESET_FLAG__", str(reset_password).lower())
              )

    return groovy

def main():
    ap = argparse.ArgumentParser(description="Create/update a Jenkins local user from a ClickUp task and grant permissions.")
    ap.add_argument("--clickup-task", required=True,
                    help="ClickUp task id to pull Email (required). This is the single argument used in CI.")
    ap.add_argument("--set-email", action="store_true", help="Store email on the user if Mailer is present")
    ap.add_argument("--reset-password", action="store_true", help="If user exists, reset password to the generated one")

    # Default baseline for new users
    default_user_perms = (
        "Overall/Read,"
        "Job/Build,Job/Cancel,Job/Configure,Job/Create,Job/Read,Job/Workspace,"
        "View/Read"
    )
    ap.add_argument("--user-perms", default=default_user_perms,
                    help="Comma-separated permission labels for the user principal.")

    ap.add_argument("--groups", default="authenticated",
                    help="Comma-separated SIDs to grant, e.g. 'authenticated,devs'")
    ap.add_argument("--group-perms", default="Overall/Read,Job/Discover,View/Read",
                    help="Comma-separated permission labels applied to each group SID")
    ap.add_argument("--jenkins-url", default=os.environ.get("JENKINS_URL", "http://localhost:8080"))
    ap.add_argument("--user",        default=os.environ.get("JENKINS_USER"))
    ap.add_argument("--token",       default=os.environ.get("JENKINS_TOKEN"))
    args = ap.parse_args()

    # Jenkins admin auth required
    if not args.user or not args.token:
        print("Error: JENKINS_USER and JENKINS_TOKEN must be supplied via env or flags --user/--token.", file=sys.stderr)
        sys.exit(2)

    # ClickUp creds required
    clickup_task_id = args.clickup_task.strip()
    clickup_api_token = os.environ.get("CLICKUP_API_TOKEN", "").strip()
    clickup_team_id = os.environ.get("CLICKUP_TEAM_ID", "").strip()
    if not clickup_api_token or not clickup_team_id:
        print("Error: CLICKUP_API_TOKEN and CLICKUP_TEAM_ID env vars are required when using --clickup-task.", file=sys.stderr)
        sys.exit(3)

    # Fetch ClickUp info and approvers (we expect an 'Email' field)
    cu = get_clickup_info(clickup_task_id, clickup_api_token, clickup_team_id)
    if not cu or not isinstance(cu, dict):
        print(json.dumps({"error": "Failed to fetch ClickUp task or parse fields", "clickup_result": cu}, indent=2), file=sys.stderr)
        sys.exit(4)

    clickup_email = cu.get("Email")
    if isinstance(clickup_email, str):
        clickup_email = clickup_email.strip().lower()
    if not clickup_email or not verify_email(clickup_email):
        print(json.dumps({"error": "ClickUp task did not contain a valid Email field", "clickup_email": clickup_email}, indent=2), file=sys.stderr)
        sys.exit(5)

    # Optional: read other ClickUp fields for audit/logging
    clickup_summary = cu.get("Summary") or cu.get("Status") or None
    clickup_team = cu.get("Team")

    # produce username and password from clickup_email
    email = clickup_email
    username = username_from_email(email)
    password = gen_password(20)

    # Parse and de-duplicate while preserving order
    def _parse_csv(s): return [p.strip() for p in s.split(",") if p.strip()]
    def _dedupe(seq):
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    user_perms = _dedupe(_parse_csv(args.user_perms))
    groups     = _dedupe(_parse_csv(args.groups))
    group_perms= _dedupe(_parse_csv(args.group_perms))

    # Build Groovy and exec
    groovy = build_groovy(username, password, email, args.set_email,
                          user_perms, groups, group_perms, args.reset_password)

    with requests.Session() as s:
        s.auth = (args.user, args.token)
        try:
            headers = get_crumb(s, args.jenkins_url)
        except Exception:
            headers = {}
        r = s.post(f"{args.jenkins_url}/scriptText",
                   data={"script": groovy}, headers=headers, timeout=60)
        r.raise_for_status()
        result_text = r.text.strip()

    # parse Groovy JSON (resilient to "Result: " prefix)
    try:
        txt = result_text
        if txt.startswith("Result:"):
            txt = txt[len("Result:"):].strip()
        groovy_json = json.loads(txt)
    except Exception:
        groovy_json = {"raw": result_text}

    # decide invite_status
    invite_status = "invited"
    events = groovy_json.get("events") if isinstance(groovy_json, dict) else None
    if isinstance(events, list):
        evtext = " ".join(events).lower()
        if any(k in evtext for k in ("created_user:", "password_reset_done", "saved_strategy")):
            invite_status = "onboarded"

    # Get ClickUp approvers for audit context
    try:
        clickup_approvers = get_clickup_approvers_from_comments(clickup_task_id, clickup_api_token, clickup_team_id)
    except Exception:
        clickup_approvers = []

    # Upsert audit entry to MongoDB (Jenkins.active_users)
    audit_ok = False
    try:
        invited_by = os.environ.get("INVITED_BY", os.environ.get("USER", "jenkins_onboard_script"))
        last_approver = clickup_approvers[-1] if clickup_approvers else None
        audit_ok = upsert_github_audit_entry(
            github_id=None,
            username=username,
            email=email,
            invited_by=invited_by,
            invite_status=invite_status,
            clickup_task_id=clickup_task_id,
            clickup_approved_by=last_approver,
            mongo_uri=os.environ.get("MONGO_URI"),
            db_name="Jenkins",
            collection_name="active_users"
        )
    except Exception as e:
        print(json.dumps({"audit_error": str(e)}, indent=2), file=sys.stderr)
        audit_ok = False

    # Final output for action logs
    out = {
        "clickup_task": clickup_task_id,
        "username": username,
        "email": email,
        "password": password,
        "user_perms": user_perms,
        "groups": groups,
        "group_perms": group_perms,
        "reset_password": args.reset_password,
        "groovy_result": groovy_json,
        "invite_status_for_audit": invite_status,
        "audit_upserted": bool(audit_ok),
        "clickup_approvers": clickup_approvers,
        "clickup_summary": clickup_summary,
        "clickup_team": clickup_team
    }
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()