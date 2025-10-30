#!/usr/bin/env python3
import os, re, sys, json, argparse, secrets, string, requests

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
    lines = []
    for p in user_perms:
        lines.append(f'grant("{p}", "{username}")')
    for g in groups:
        for p in group_perms:
            lines.append(f'grant("{p}", "{g}")')

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
""".strip() if set_email else "// Email setting skipped by flag\n"

    reset_block = """
// Reset password on existing user as requested
def details = HudsonPrivateSecurityRealm.Details.fromPlainPassword(PASSWORD)
u.addProperty(details)
u.save()
""".strip() if reset_password else "// Password reset skipped\n"

    return f"""
import jenkins.model.Jenkins
import hudson.security.*
import hudson.model.User
import groovy.transform.Field

def j = Jenkins.get()

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
}} else {{
  {reset_block}
}}

{email_block}

// Ensure Global Matrix strategy
def strategy = j.getAuthorizationStrategy()
if (!(strategy instanceof GlobalMatrixAuthorizationStrategy)) {{
  strategy = new GlobalMatrixAuthorizationStrategy()
}}

// Label → Permission constants (Jenkins 2.289.x)
@Field Map<String,Object> PERM = [
  "Overall/Administer": jenkins.model.Jenkins.ADMINISTER,
  "Overall/Read"     : jenkins.model.Jenkins.READ,
  "Job/Build"        : hudson.model.Item.BUILD,
  "Job/Cancel"       : hudson.model.Item.CANCEL,
  "Job/Discover"     : hudson.model.Item.DISCOVER,
  "Job/Read"         : hudson.model.Item.READ,
  "View/Read"        : hudson.model.View.READ
]

// Helper: add a grant
def grant(String label, String sid) {{
  def p = PERM[label]
  if (p == null) {{
    throw new IllegalArgumentException("Unknown permission label: " + label)
  }}
  try {{
    strategy.add(p, sid)
  }} catch (Throwable t) {{
    // ignore duplicates on older lines
  }}
}}

{chr(10).join(lines)}

j.setAuthorizationStrategy(strategy)
j.save()

return "OK:USER=" + USERNAME
""".strip()

def main():
    ap = argparse.ArgumentParser(description="Create/update a Jenkins local user from email and grant permissions.")
    ap.add_argument("--email", required=True, help="Email of the user to onboard")
    ap.add_argument("--set-email", action="store_true", help="Store email on the user if Mailer is present")
    ap.add_argument("--reset-password", action="store_true", help="If user exists, reset password to the generated one")
    ap.add_argument("--user-perms", default="Job/Build",
                    help="Comma-separated permission labels for the user principal, e.g. 'Job/Build,Job/Cancel'")
    ap.add_argument("--groups", default="authenticated",
                    help="Comma-separated SIDs to grant, e.g. 'authenticated,devs'")
    ap.add_argument("--group-perms", default="Overall/Read,Job/Discover,View/Read",
                    help="Comma-separated permission labels applied to each group SID")
    ap.add_argument("--jenkins-url", default=os.environ.get("JENKINS_URL", "http://localhost:8080"))
    ap.add_argument("--user",        default=os.environ.get("JENKINS_USER"))
    ap.add_argument("--token",       default=os.environ.get("JENKINS_TOKEN"))
    args = ap.parse_args()

    if not args.user or not args.token:
        print("Error: JENKINS_USER and JENKINS_TOKEN must be supplied via env or flags --user/--token.", file=sys.stderr)
        sys.exit(2)

    email = args.email.strip()
    username = username_from_email(email)
    password = gen_password(20)

    user_perms = [p.strip() for p in args.user_perms.split(",") if p.strip()]
    groups     = [g.strip() for g in args.groups.split(",") if g.strip()]
    group_perms= [p.strip() for p in args.group_perms.split(",") if p.strip()]

    groovy = build_groovy(username, password, email, args.set_email, user_perms, groups, group_perms, args.reset_password)

    with requests.Session() as s:
        s.auth = (args.user, args.token)
        try:
            headers = get_crumb(s, args.jenkins_url)
        except Exception:
            headers = {}
        r = s.post(f"{args.jenkins_url}/scriptText",
                   data={"script": groovy}, headers=headers, timeout=60)
        r.raise_for_status()
        result = r.text.strip()

    print(json.dumps({
        "username": username,
        "email": email,
        "password": password,
        "user_perms": user_perms,
        "groups": groups,
        "group_perms": group_perms,
        "reset_password": args.reset_password,
        "result": result
    }, indent=2))

if __name__ == "__main__":
    main()