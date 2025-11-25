import os
import logging
import requests
import json, re
import time
from typing import Optional
import sys
from pathlib import Path
import boto3
from botocore.exceptions import ClientError
import certifi
from pymongo import MongoClient
from datetime import datetime

try:
    from config import MONGO_URI as CONFIG_MONGO_URI, MONGO_DB_NAME, MONGO_ACTIVE_COLLECTION, MONGO_OFFBOARDED_COLLECTION
except Exception:
    CONFIG_MONGO_URI = None
    MONGO_DB_NAME = None
    MONGO_ACTIVE_COLLECTION = None
    MONGO_OFFBOARDED_COLLECTION = None

API_BASE = "https://api.github.com"
HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "sc-infra-vpn-butler-onboard-script"
}

def verify_email(email):
    if email is None:  # Skip verification if email is None
        return True
    if not isinstance(email, str):  # Ensure it's a string
        return False
    return bool(re.match(r'^[a-zA-Z0-9_.+-]+@(smallcase\.com|tickertape\.in)$', email))

def get_secret(secret_name, region_name="ap-south-1"):
    try:
        client = boto3.session.Session().client(
            service_name='secretsmanager', region_name=region_name
        )
        secret_value = client.get_secret_value(SecretId=secret_name)
        return json.loads(secret_value['SecretString'])
    except ClientError as e:
        logging.exception(f"Failed to get secret {secret_name}: {e}")
        raise

def add_value_to_existing_secret(secret_name, new_data, region_name="ap-south-1"):
    logging.basicConfig(level=logging.INFO)
    client = boto3.client("secretsmanager", region_name=region_name)

    # Ensure the new data is a dictionary
    if not isinstance(new_data, dict):
        raise ValueError("The 'new_data' parameter must be a dictionary.")

    try:
        # Fetch the current value of the secret
        response = client.get_secret_value(SecretId=secret_name)
        current_secret = response.get("SecretString", "{}")

        # Parse the current secret as JSON
        try:
            current_secret = json.loads(current_secret)
            if not isinstance(current_secret, dict):
                logging.warning(f"Secret '{secret_name}' is not a JSON object. Converting it to a dictionary.")
                current_secret = {}
        except json.JSONDecodeError:
            logging.warning(f"Secret '{secret_name}' contains invalid JSON. Converting it to an empty dictionary.")
            current_secret = {}

        # Add new key-value pairs to the existing secret without replacing it
        for key, value in new_data.items():
            if key in current_secret:
                logging.info(f"Key '{key}' already exists in the secret. Updating its value.")
            current_secret[key] = value

        # Update the secret in Secrets Manager
        client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(current_secret)
        )
        logging.info(f"Secret '{secret_name}' successfully updated with new values.")
        return True

    except client.exceptions.ResourceNotFoundException:
        logging.error(f"Secret '{secret_name}' not found.")
        return False
    except Exception as e:
        logging.error(f"Unexpected error while updating secret '{secret_name}': {e}")
        return False

def remove_value_from_secret(secret_name, key, region_name="ap-south-1"):

    logging.basicConfig(level=logging.INFO)
    client = boto3.client("secretsmanager", region_name=region_name)

    try:
        # Fetch the current value of the secret
        response = client.get_secret_value(SecretId=secret_name)
        current_secret = response.get("SecretString", "{}")

        # Parse the current secret as JSON
        try:
            current_secret = json.loads(current_secret)
            if not isinstance(current_secret, dict):
                logging.warning(f"Secret '{secret_name}' is not a JSON object. Skipping removal.")
                return False
        except json.JSONDecodeError:
            logging.warning(f"Secret '{secret_name}' contains invalid JSON. Skipping removal.")
            return False

        # Remove the specified key
        if key in current_secret:
            logging.info(f"Removing key '{key}' from the secret.")
            del current_secret[key]
        else:
            logging.info(f"Key '{key}' not found in the secret. Skipping.")
            return False  # No update needed if the key isn't present

        # Update the secret in Secrets Manager
        client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(current_secret)
        )
        logging.info(f"Secret '{secret_name}' successfully updated after key removal.")
        return True

    except client.exceptions.ResourceNotFoundException:
        logging.error(f"Secret '{secret_name}' not found.")
        return False
    except Exception as e:
        logging.error(f"Unexpected error while updating secret '{secret_name}': {e}")
        return False

def get_clickup_info(task_id, api_token, team_id):
    def map_group(account, env, resource_type, db_name=None):
        if isinstance(resource_type, list):
            resource_type = resource_type[0] if resource_type else None
        if not account or not env or not resource_type:
            return None
        account = account.strip().lower()
        env = env.strip().lower()
        resource_type = 'db' if resource_type.strip().lower() in {'atlas', 'docdb'} else 'vpn' if resource_type.strip().lower() == 'vpn' else resource_type.strip().lower()
        db_name = db_name.strip().lower() if db_name else None
        # Mapping for VPN access
        VPN_MAPPING = {
            'smallcase': 'AT-PROD',
            'las': 'LAS-PROD',
            'test': "TEST",
        }
        # Special DB-specific mapping
        DB_MAPPING = {
            'smallcase': {
                'smallcase-prod': {
                    'production': 'AT-PROD',
                    'staging': 'AT-STAG',
                },
                'tt-prod': {
                    'production': 'TT-PROD',
                    'staging': 'TT-STAG',
                },
                'tt-be-platform-ecosystem': {
                    'production': 'TT-PROD',
                    'staging': 'TT-STAG',
                },
                'test': {
                    'production': "TEST",
                }
            },
            'las': {
                'las-production': {
                    'production': 'LAS-PROD',
                },
                'unity-production': {
                    'production': 'UNITY-PROD',
                },
                'nexum-production': {
                    'production': 'NEXUM-PROD',
                },
                'test': {
                    'production': "TEST",
                }
            }
        }
        if resource_type == 'vpn':
            return VPN_MAPPING.get(account)

        elif resource_type == 'db':
            # Try DB-specific mapping first
            if db_name and account in DB_MAPPING:
                db_map = DB_MAPPING[account].get(db_name)
                if db_map:
                    return db_map.get(env)
        return None
    
    def map_permissions(db_access):
        """Map DB Access field to permission actions"""
        PERMISSION_MAPPING = {
            'read': ['FIND', 'LIST_COLLECTIONS'], 
            'readwrite': ['FIND', 'INSERT', 'UPDATE', 'REMOVE', 'LIST_COLLECTIONS'],
        }
        
        logging.info(f"map_permissions received: '{db_access}' (type: {type(db_access)})")
        
        if not db_access:
            logging.info("db_access is empty, returning default ['FIND', 'LIST_COLLECTIONS']")
            return ['FIND', 'LIST_COLLECTIONS']  
            
        db_access_lower = db_access.strip().lower()
        logging.info(f"After strip().lower(): '{db_access_lower}'")
        if db_access_lower in ('read-only', 'readonly'):
            db_access_lower = 'read'
        if db_access_lower in ('read/write', 'read write', 'readwrite'):
            db_access_lower = 'readwrite'
        result = PERMISSION_MAPPING.get(db_access_lower, ['FIND', 'LIST_COLLECTIONS'])
        logging.info(f"PERMISSION_MAPPING result: {result}")
        return result

    def clickup_resolve_option_name(value_id, options):
        """
        Try multiple ways to map a ClickUp stored value (id/orderindex/value) to the option label/name/value.
        Return a string when sensible, else None.
        """
        if value_id is None:
            return None
        vid = str(value_id)
        for opt in (options or []):
            # compare as strings to handle numeric ids or strings
            if str(opt.get('id', '')) == vid or str(opt.get('orderindex', '')) == vid or str(opt.get('value', '')) == vid:
                return opt.get('name') or opt.get('label') or opt.get('value')
        # If not found, attempt relaxed matching: compare option.value/name lowercased
        lvid = vid.strip().lower()
        for opt in (options or []):
            for candidate in (opt.get('name'), opt.get('label'), opt.get('value')):
                if isinstance(candidate, str) and candidate.strip().lower() == lvid:
                    return candidate
        # final fallback: return stringified value_id so upstream normalizer can still work
        return None
    
    def _resolve_field(value, options):
        """Return a sensible string/email/list for ClickUp field values (handles str/list/dict).
           If options are provided and the value looks like an option id, resolve to the option name.
        """
        if value is None:
            return None

        # If value is a primitive (str/int/float) but options are present,
        # try to resolve it as an option id/value/orderindex first.
        if isinstance(value, (str, int, float)):
            # try resolve via options
            resolved = clickup_resolve_option_name(value, options) if options else None
            if resolved is not None:
                return resolved
            # fallback to plain string
            return str(value)

        # Lists: typically ClickUp returns list-of-objects or list-of-strings for multi-selects/users
        if isinstance(value, list) and value:
            first = value[0]
            # list of simple strings
            if isinstance(first, str):
                # try to resolve this string against options too
                if options:
                    resolved = clickup_resolve_option_name(first, options)
                    if resolved is not None:
                        return resolved
                return first
            # list of dicts (user objects or option objects)
            if isinstance(first, dict):
                # if it's a user-like dict, prefer email
                if 'email' in first and isinstance(first['email'], str):
                    return first['email']
                # common keys in option dicts
                for k in ("value", "name", "label", "text"):
                    if k in first and isinstance(first[k], str):
                        return first[k]
                # fallback: try to resolve by id/value/orderindex fields inside the dict
                id_candidate = first.get("id") or first.get("value") or first.get("orderindex")
                if id_candidate is not None and options:
                    resolved = clickup_resolve_option_name(id_candidate, options)
                    if resolved is not None:
                        return resolved
                # last fallback: stringified representation
                return str(first)

        # If value is a dict: try to pick useful string fields or resolve by id
        if isinstance(value, dict):
            for k in ("value", "name", "label", "text"):
                if k in value and isinstance(value[k], str):
                    return value[k]
            id_candidate = value.get("id") or value.get("value") or value.get("orderindex")
            if id_candidate is not None and options:
                resolved = clickup_resolve_option_name(id_candidate, options)
                if resolved is not None:
                    return resolved
            return None

        # Other types: fallback to string
        return str(value)
                 
    url = f"https://api.clickup.com/api/v2/task/{task_id}"
    headers = {"Authorization": api_token}
    params = {
        "custom_task_ids": "true",
        "team_id": team_id,
        "include_subtasks": "false",
        "include_markdown_description": "false",
        "custom_fields": "string"
    }
    extracted_info = {
        'Status': None,
        'Duration': None,
        'Email': None,
        'Team': None,
        'Type': [],
        'Account': None,
        'Database': None,
        'Env': None,
        'Approver': [],
        'Group': None,
        'DBRole': None,
        'Collections': [],
        'GitHub': None,

    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        response = response.json()
        # get status
        extracted_info['Status'] = response['status']['status'].lower()
        # Parse custom fields
        for field in response.get('custom_fields', []):
            name = field.get('name')
            value = field.get('value')
            options = field.get('type_config', {}).get('options', [])
            logging.debug("ClickUp custom field raw: name=%r, value=%r, options_count=%d", name, value, len(options) if options is not None else 0)

            field_name = (name or "").strip().lower()

            if field_name == 'duration':
                resolved = _resolve_field(value, options)
                if resolved is None or resolved == "":
                    extracted_info['Duration'] = None
                else:
                    try:
                        extracted_info['Duration'] = int(str(resolved).strip().split()[0])
                    except Exception:
                        extracted_info['Duration'] = resolved
            elif field_name == 'email':
                resolved = _resolve_field(value, options)
                extracted_info['Email'] = resolved.lower() if isinstance(resolved, str) else None
            elif field_name in ('github username', 'github', 'github_username', 'github-user', 'githubuser'):
                resolved = _resolve_field(value, options)
                if isinstance(resolved, str):
                    username = resolved.strip()
                    if username.startswith("@"):
                        username = username[1:]
                    extracted_info['GitHub'] = username
                else:
                    extracted_info['GitHub'] = None
            elif field_name == 'team':
                resolved = _resolve_field(value, options)
                if isinstance(resolved, str):
                    team_norm = resolved.strip().lower()
                    TEAM_MAP = {
                        'platform ( foundation / experience )': 'platform',
                        'platform': 'platform',
                        'integrations': 'integrations',
                        'gateway': 'gateway',
                        'comms': 'comms',
                        'publisher': 'publisher',
                        'tickertape': 'tickertape',
                        'windmill': 'windmill',
                        'infra': 'infra',
                    }
                    extracted_info['Team'] = TEAM_MAP.get(team_norm, team_norm)
                else:
                    extracted_info['Team'] = None
            elif field_name in ('aws account', 'account'):
                resolved = _resolve_field(value, options)
                extracted_info['Account'] = resolved.lower() if isinstance(resolved, str) else None
            elif field_name in ('env', 'environment'):
                resolved = _resolve_field(value, options)
                extracted_info['Env'] = resolved.lower() if isinstance(resolved, str) else None
            elif field_name == 'type':
                resolved = _resolve_field(value, options)
                extracted_info['Type'] = resolved if resolved else []
            elif field_name == 'database':
                resolved = _resolve_field(value, options)
                extracted_info['Database'] = resolved.lower() if isinstance(resolved, str) else None
            elif field_name in ('db access', 'mongodb access', 'mongo db access', 'mongodbaccess', 'mongodb access '):
                # robust resolution for DB access field (handles many ClickUp shapes)
                resolved = _resolve_field(value, options)

                # If _resolve_field didn't find a friendly name but options exist, attempt extra resolution
                if (resolved is None or resolved == "") and options:
                    # try list/dict inside value to find id/value/orderindex then map via options
                    if isinstance(value, list) and value:
                        first = value[0]
                        if isinstance(first, dict):
                            cand = first.get("id") or first.get("value") or first.get("orderindex")
                        else:
                            cand = first
                        resolved = clickup_resolve_option_name(cand, options) or resolved
                    elif isinstance(value, dict):
                        cand = value.get("id") or value.get("value") or value.get("orderindex")
                        resolved = clickup_resolve_option_name(cand, options) or resolved
                    else:
                        resolved = clickup_resolve_option_name(value, options) or resolved

                # Normalize common forms to either 'read' or 'readwrite' or keep literal
                if isinstance(resolved, str) and resolved:
                    r = resolved.strip().lower()
                    if r in ('read-only', 'readonly', 'read only'):
                        normalized = 'read'
                    elif r in ('readwrite', 'read/write', 'read write'):
                        normalized = 'readwrite'
                    else:
                        normalized = r
                    extracted_info['DBRole'] = normalized
                else:
                    extracted_info['DBRole'] = None

                # map to actionable permissions (map_permissions handles None)
                extracted_info['actions'] = map_permissions(extracted_info.get('DBRole'))
                logging.debug(
                    "DB access raw value: %r, options_count: %d, resolved: %r, normalized role: %r",
                    value,
                    len(options) if options is not None else 0,
                    resolved,
                    extracted_info['DBRole']
                )
            elif field_name == 'approver':
                if isinstance(value, list):
                    extracted_info['Approver'] = [u.get('email') for u in value if isinstance(u, dict) and u.get('email')]
                else:
                    extracted_info['Approver'] = []

            elif field_name in ('collection(s)', 'collections', 'collection'):
                if isinstance(value, list):
                    extracted_info['Collections'] = [col.strip() for col in value if isinstance(col, str) and col.strip()]
                elif isinstance(value, str) and value:
                    collections = value.replace('\n', ',').split(',')
                    extracted_info['Collections'] = [col.strip() for col in collections if col.strip()]
                else:
                    extracted_info['Collections'] = []

        # Fallback: if DBRole is still None, try to find any custom field whose name contains
        # both 'mongo' and 'access' (handles slight naming variations like "MongoDB Access")
        if not extracted_info.get('DBRole'):
            for field in response.get('custom_fields', []):
                fname = (field.get('name') or "").strip().lower()
                if 'mongo' in fname and 'access' in fname:
                    fvalue = field.get('value')
                    foptions = field.get('type_config', {}).get('options', [])
                    resolved = _resolve_field(fvalue, foptions)

                    # If resolved is empty but options exist, try resolving via id/orderindex/value
                    if (resolved is None or resolved == "") and foptions:
                        if isinstance(fvalue, list) and fvalue:
                            first = fvalue[0]
                            cand = first.get("id") if isinstance(first, dict) else first
                        elif isinstance(fvalue, dict):
                            cand = fvalue.get("id") or fvalue.get("value") or fvalue.get("orderindex")
                        else:
                            cand = fvalue
                        resolved = clickup_resolve_option_name(cand, foptions) or resolved

                    if isinstance(resolved, str) and resolved:
                        r = resolved.strip().lower()
                        if r in ('read-only', 'readonly', 'read only'):
                            normalized = 'read'
                        elif r in ('readwrite', 'read/write', 'read write'):
                            normalized = 'readwrite'
                        else:
                            normalized = r
                        extracted_info['DBRole'] = normalized
                    else:
                        extracted_info['DBRole'] = None

                    extracted_info['actions'] = map_permissions(extracted_info.get('DBRole'))
                    logging.debug("Fallback DBRole resolved from field %r -> %r", fname, extracted_info['DBRole'])
                    break
                                
        extracted_info['Group'] = map_group(
            extracted_info.get('Account'), 
            extracted_info.get('Env'), 
            extracted_info.get('Type'), 
            extracted_info.get('Database')
        )
        logging.info("ClickUp parsed: Email=%s Approvers=%s DBRole=%s", 
                     extracted_info.get('Email'),
                     extracted_info.get('Approver'),
                     extracted_info.get('DBRole'))
        # If DBRole still couldn't be resolved, dump the raw custom_fields for debugging.
        if not extracted_info.get('DBRole'):
            logging.warning(
                "DBRole could not be resolved from ClickUp custom fields for task %s. Dumping raw custom_fields for debugging.", 
                task_id
            )
            for f in response.get('custom_fields', []):
                logging.debug("CF DUMP -> name=%r, value=%r, type_config=%r", f.get('name'), f.get('value'), f.get('type_config'))
        return extracted_info
    except requests.RequestException as e:
        logging.error(f"Error accessing ClickUp API: {e}")
        return False, "ClickUp access error"
    except KeyError:
        logging.error("Unexpected response format from ClickUp API")
        return False, "ClickUp response error"


def is_clickup_approved(team_name, task_id, api_token, team_id, staging=False, environment=None, database=None):
    # Decide if this is staging using explicit flag or ClickUp fields or fallback
    base_path = Path(__file__).resolve().parent.parent
    env_val = (environment or "").strip().lower() if environment is not None else ""
    db_val = (database or "").strip().lower() if database is not None else ""
    team_upper = team_name.upper() if isinstance(team_name, str) else ""
    is_staging_env = False
    if staging:
        is_staging_env = True
    elif env_val and env_val == "staging":
        is_staging_env = True
    elif db_val and ("stag" in db_val or "staging" in db_val):
        is_staging_env = True
    elif team_upper in ["AT-STAG", "TT-STAG"]: # backward-compat fallback
        is_staging_env = True
    
    try:
        if is_staging_env:
            stag_path = base_path / "approval_matrix_staging.yaml"
            with open(stag_path, "r") as f:
                stag_data = yaml.safe_load(f)
            if isinstance(stag_data, dict):
                stag_approvers = stag_data.get("approvers") or stag_data.get("emails") or []
            elif isinstance(stag_data, list):
                stag_approvers = stag_data
            else: 
                logging.error("Invalid format in approval_matrix_staging.yaml; expected list or dict with 'approvers'")
                return False
            stag_approvers = [e.lower().strip() for e in stag_approvers if isinstance(e, str)]
        else:
            matrix_path = base_path / "approval_matrix.yaml"
            with open(matrix_path, "r") as f:
                approval_matrix = yaml.safe_load(f).get("approval_matrix", {})
    except Exception as e:
        logging.exception(f"Error loading approval matrix file: {e}")
        return False

    # try:
    #     with open(Path(__file__).resolve().parent.parent / "approval_matrix.yaml", "r") as f:
    #         approval_matrix = yaml.safe_load(f)["approval_matrix"]
    # except Exception as e:
    #     logging.error(f"Error loading approval matrix: {e}")

    def check_approval_intent(text, intent="positive"):
        text = text.lower()
        pattern_dict = {
            "negative_patterns": {
                "not_approve": re.compile(r"\bnot[\s\-_]*approv", re.IGNORECASE),
                "disapprove": re.compile(r"\bdis[\s\-_]*approv", re.IGNORECASE),
                "decline": re.compile(r"\bdeclin(?:e|ed|ing)?\b", re.IGNORECASE),
                "will_not_approve": re.compile(r"\bwill\s+not\s+approve\b", re.IGNORECASE),
                "reject": re.compile(r"\breject(?:ed|ion)?\b", re.IGNORECASE)
            },
            "positive_patterns": {
                "approved_or_approving": re.compile(r"\bapprov(?:ed|ing)\b", re.IGNORECASE)
            },
            "future_approval_pattern": {
                "will_approve": re.compile(r"\bwill\s+approve\b", re.IGNORECASE),
                "later_approve": re.compile(r"\blater\s+approve\b", re.IGNORECASE),
                "soon_approve": re.compile(r"\bsoon\s+approve\b", re.IGNORECASE)
            }
        }
        if intent == "positive":
            if any(p.search(text) for p in pattern_dict["positive_patterns"].values()):
                if not any(p.search(text) for p in pattern_dict["negative_patterns"].values()) \
                and not any(p.search(text) for p in pattern_dict["future_approval_pattern"].values()):
                    return True
            return False
        elif intent == "negative":
            return any(p.search(text) for p in pattern_dict["negative_patterns"].values())
        elif intent == "future":
            return any(p.search(text) for p in pattern_dict["future_approval_pattern"].values())
        return False

    def get_task_comments():
        try:
            url = f"https://api.clickup.com/api/v2/task/{task_id}/comment"
            headers = {'Authorization': api_token}
            params = {
                "custom_task_ids": "true",
                "team_id": team_id,
                "include_subtasks": "false",
                "include_markdown_description": "false",
            }
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()

            all_comments = []
            for comment in sorted(response.json().get("comments", []), key=lambda x: x.get("date", 0)):
                user = comment.get("user", {})
                author_email = user.get("email", "").lower()
                text_segments = comment.get("comment", [])
                full_text = "".join(seg.get("text", "") for seg in text_segments).strip().lower()

                if full_text:
                    all_comments.append({
                        "author_email": author_email,
                        "text": full_text
                    })

            return all_comments
        except requests.RequestException as e:
            logging.exception(f"Error accessing ClickUp API: {e}")
            return False, "ClickUp access error"
        except KeyError:
            logging.exception("Unexpected response format from ClickUp API")
            return False, "ClickUp response error"
   

    comments = get_task_comments()

    if is_staging_env:
        if isinstance(comments, tuple) and comments[0] is False:
            return False
        approve_pattern = re.compile(r"\bapprove(?:d|s)?\b", re.IGNORECASE)
        for comment in comments:
            author = (comment.get("author_email") or "").lower().strip()
            text = comment.get("text", "") or ""
            if author in stag_approvers and approve_pattern.search(text):
                logging.info(f"Staging approval found from {author}: {text[:120]}")
                return True
        logging.info("No valid staging approval comment found.")
        return False
    
    if not is_staging_env:
        if not team_name:
            raise ValueError("Missing team_name required for prod approval lookup")

        team_name = team_name.strip().lower() 
        if team_name not in approval_matrix:
            raise ValueError(f"Team '{team_name}' not found in approval matrix.")

        team_info = approval_matrix[team_name]
        required_approvers = [team_info["primary"].lower(), team_info["secondary"].lower()]

        if isinstance(comments, tuple) and comments[0] is False:
            return False

        approver_status = {approver: [] for approver in required_approvers}

        for comment in comments:
            email = comment["author_email"]
            text = comment["text"]
            if email in approver_status:
                approver_status[email].append(text)

        for approver, comment_texts in approver_status.items():
            last_intent = None
            for text in comment_texts:
                if check_approval_intent(text, intent="negative"):
                    last_intent = "rejected"
                elif check_approval_intent(text, intent="positive"):
                    last_intent = "approved"
            if last_intent != "approved":
                return False  # either rejected last or never approved
        return True


def clickup_comment(task_id, comment, api_token, team_id, if_offboard=False, update_status=True):
    url = f"https://api.clickup.com/api/v2/task/{task_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": api_token
    }
    params = {
        "custom_task_ids": "true",
        "team_id": team_id
    }
    payload = {
        "comment_text": comment,
        "notify_all": True
    }

    try:
        response = requests.post(url+"/comment", headers=headers, params=params, json=payload)
        response.raise_for_status()
        logging.info("ClickUp comment added successfully")
        
        if update_status:
            if if_offboard:
                status = "Done"
            else:
                status = "ACCESS GRANTED"
            resp = requests.put(url, headers=headers, params=params, json={"status": f"{status}"})
            resp.raise_for_status()
            logging.info(f"ClickUp task status updated to - {status}")
        else:
            logging.info("ClickUp comment added (status not updated)")
            
        return True
    except requests.RequestException as e:
        logging.error(f"Error adding comment: {e}")
        return False
    
def get_google_service(google_credentials, scopes, subject="muhammad.shareek@smallcase.com"):
    credentials = ServiceAccountCredentials.from_service_account_info(
        google_credentials, scopes=scopes, subject=subject
    )
    return build('admin', 'directory_v1', credentials=credentials)

def fetch_existing_groups(user_email, google_credentials):
    try:
        logging.info("Fetching existing google groups")
        service = get_google_service(google_credentials, [
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://www.googleapis.com/auth/admin.directory.group"
        ])
        domain = "tickertape.in" if user_email.endswith("tickertape.in") else "smallcase.com"
        response = service.groups().list(domain=domain, userKey=user_email).execute()
        email_list = [group['email'] for group in response.get("groups", [])]
        logging.info(email_list)
        return email_list
    except Exception as e:
        logging.exception(f"Unable to check existing google groups: {e}")
        return []

def send_webhook(message, msg_type="text", channel="temp-access-alerts-testing"): # for testing
# def send_webhook(message, msg_type="text", channel="temp-access-alerts"):
    logging.info(f"Sending webhook to {channel}")
    try:
        HOOK = get_secret("vpn-butler-mongo-admin")['SLACK_HOOK_TEST']  # for testing
        # HOOK = get_secret("vpn-butler-mongo-admin")['SLACK_HOOK']
        payload = {
            "channel": channel
        }
        if msg_type == "text" and isinstance(message, str) and re.search(r"<https?://[^|]+?\|[^>]+?>", message):
            msg_type = "blocks"
            message = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        if msg_type == "blocks":
            payload.update({ "blocks": message })
        else:
            payload.update({ "text": message })
        response = requests.post(HOOK,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(payload)
        )
        logging.info(f"Response from slack webhook - {response.text}")
        if response.status_code != 200:
            logging.error(f"Failed to send message to Slack. Status code: {response.status_code}")
    except Exception as e:
        logging.exception(f"Failed to send slack webhook: {e}")
def send_email(subject, message, recipient):
    logging.info("Sending email")
    try:
        ses_client = boto3.client('ses', region_name='ap-south-1')  # Replace with your region
        response = ses_client.send_email(
            Source="infra@smallcase.com",
            Destination={
                'ToAddresses': [recipient],
                },
            Message={
                'Subject': {
                    'Data': subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': message,
                        'Charset': 'UTF-8'
                    },
                    'Text': {
                        'Data': "This is a fallback plain text message for butler. Contact to infra POC",
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        logging.info(f"Email sent successfully to {recipient}, Message ID: {response['MessageId']}")
        return True
    except ClientError as e:
        logging.error(f"SES ClientError: {e.response['Error']['Code']} - {e.response['Error']['Message']}")
        return False
    except Exception as e:
        logging.exception(f"Failed to send email: {e}")
        return False

def check_existing_pr(repo, branch_name):
    prs = repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch_name}")
    return prs[0] if prs.totalCount > 0 else None

def merge_pull_request(pull_request_url):
    try:
        git_token = os.getenv("GIT_TOKEN")
        g = Github(git_token)
        repo_owner = os.getenv("GIT_REPO_OWNER")
        repo_name = os.getenv("SC_INFRA_TF_MONGODB_ATLAS_REPO")
        repo = g.get_repo(f"{repo_owner}/{repo_name}")
        
        pr_number = int(pull_request_url.split('/')[-1])
        pr = repo.get_pull(pr_number)
        
        if not pr.mergeable:
            logging.error("Pull request is not mergeable")
            return False
            
        pr.merge(
            merge_method="squash",
            commit_message=f"Auto-merge: {os.getenv('PR_TITLE')}"
        )
        return True
        
    except Exception as e:
        logging.error(f"Failed to merge pull request: {str(e)}")
        return False

def delete_branch(branch_name):
    try:
        git_token = os.getenv("GIT_TOKEN")
        g = Github(git_token)
        repo_owner = os.getenv("GIT_REPO_OWNER")
        repo_name = os.getenv("SC_INFRA_TF_MONGODB_ATLAS_REPO")
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        ref = f"heads/{branch_name}"
        ref_obj = repo.get_git_ref(ref)
        
        if ref_obj:
            ref_obj.delete()
            logging.info(f"Branch '{branch_name}' deleted")
            return True
            
        return False
        
    except Exception as e:
        logging.error(f"Failed to delete branch: {str(e)}")
        return False

def git_add_and_create_pull_request(value_file, custom_role_value_file, branch_name):
    repo_owner = os.getenv("GIT_REPO_OWNER")
    repo_name = os.getenv("SC_INFRA_TF_MONGODB_ATLAS_REPO")
    git_token = os.getenv("GIT_TOKEN")
    git_user_mail = os.getenv("GIT_USER_MAIL")
    git_username = os.getenv("GIT_USERNAME")
    commit_msg = os.getenv("COMMIT_MSG")
    pr_title = os.getenv("PR_TITLE")
    base_branch = os.getenv("SC_INFRA_TF_MONGODB_ATLAS_REPO_BRANCH")
    repo_base = "/home/runner/_work/sc-infra-vpn-butler/sc-infra-vpn-butler"
    repo_path = f"{repo_base}/{repo_name}"
    try:
        # Initialize GitHub
        g = Github(git_token)
        github_repo = g.get_repo(f"{repo_owner}/{repo_name}")
        
        # Check existing PR
        existing_pr = check_existing_pr(github_repo, branch_name)
        if existing_pr:
            logging.info(f"An existing PR is already open: {existing_pr.html_url}")
            return f"Existing PR: {existing_pr.html_url}"
            
        # Local git operations
        if not os.path.exists(repo_path):
            raise Exception("Repository directory not found")
            
        repo = Repo(repo_path)
        
        # Configure git
        repo.config_writer().set_value("user", "email", git_user_mail).release()
        repo.config_writer().set_value("user", "name", git_username).release()
        
        # Fetch and branch handling
        repo.git.fetch('--all')
        
        if branch_name in repo.heads:
            logging.info(f"{branch_name} is already existing switching branch")
            branch = repo.heads[branch_name]
            branch.checkout()
            repo.git.config('pull.rebase', 'true')
            repo.git.pull()
            repo.git.pull('origin', branch_name)
        else:
            logging.info(f"{branch_name} is doesn't existing creating new branch")
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()
            
        # Check for changes
        files_to_check = [f"{repo_base}/{repo_name}/{value_file}"]
        if custom_role_value_file:
            files_to_check.append(f"{repo_base}/{repo_name}/{custom_role_value_file}")
        
        status = repo.git.ls_files('--modified', *files_to_check)
        untracked = repo.git.ls_files('--others', '--exclude-standard', *files_to_check)
        
        if status or untracked:
            # Add and commit changes
            repo.index.add([value_file, custom_role_value_file] if custom_role_value_file else [value_file])
            repo.index.commit(f"chore: {commit_msg}")
            
            # Push changes
            origin = repo.remote('origin')
            origin.push(refspec=f"refs/heads/{branch_name}:refs/heads/{branch_name}")
            
            # Create PR
            pr = github_repo.create_pull(
                title=pr_title,
                body="Pull Request Description",
                head=branch_name,
                base=base_branch
            )
            logging.info(f"New Pull Request has been created {pr.html_url} ")
            return f"New PR: {pr.html_url}"
        else:
            if os.getenv('GITHUB_OUTPUT'):
                with open(os.getenv('GITHUB_OUTPUT'), 'a') as f:
                    f.write("NO_CHANGES=true\n")
            return None
            
    except Exception as e:
        logging.error(f"Error in PR creation: {str(e)}")
        return None

def get_clickup_approvers_from_comments(task_id, api_token, team_id):
    """
    Return a list of author_email strings from ClickUp comments that contain
    approval intent (e.g. 'approve', 'approved'). Returns [] if none or on error.
    """
    try:
        url = f"https://api.clickup.com/api/v2/task/{task_id}/comment"
        headers = {'Authorization': api_token}
        params = {
            "custom_task_ids": "true",
            "team_id": team_id,
            "include_subtasks": "false",
            "include_markdown_description": "false",
        }
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        comments = resp.json().get("comments", [])
        # sort chronologically
        comments_sorted = sorted(comments, key=lambda x: x.get("date", 0))
        approve_re = re.compile(r"\bapprov(?:ed|ing)?\b", re.IGNORECASE)
        negative_re = re.compile(r"\b(not[\s\-_]*approv|dis[\s\-_]*approv|declin(?:e|ed|ing)?|reject)\b", re.IGNORECASE)

        approvers = []
        for c in comments_sorted:
            user = c.get("user", {})
            author_email = (user.get("email") or "").lower().strip()
            # comment text may be segmented
            text_segments = c.get("comment", [])
            full_text = "".join(seg.get("text", "") for seg in text_segments).strip()
            if not full_text or not author_email:
                continue
            # positive only if contains approve-like token and not explicit negative
            if approve_re.search(full_text) and not negative_re.search(full_text):
                if author_email not in approvers:
                    approvers.append(author_email)
        return approvers
    except requests.RequestException as e:
        logging.exception("Error fetching ClickUp comments for approval: %s", e)
        return []
    except Exception as e:
        logging.exception("Unexpected error parsing clickup comments: %s", e)
        return []

def upsert_github_audit_entry(github_id: int,
                              username: str | None,
                              email: str | None,
                              invited_by: str | None = None,
                              invite_status: str = "invited",
                              clickup_task_id: Optional[str] = None,
                              clickup_approved_by: Optional[str] = None,
                              mongo_uri: Optional[str] = None,
                              db_name: str | None = None,
                              collection_name: str | None = None) -> bool:
    """
    Upsert an audit record for onboarding.
    Resolution order for Mongo URI: explicit mongo_uri param -> MONGO_URI env var -> config.py CONFIG_MONGO_URI
    For db_name/collection_name: explicit param -> provided config vars -> sensible defaults (Github/active_users).
    Returns True on success, False on failure.
    """
    try:
        # Resolve URI
        uri = mongo_uri or os.environ.get("MONGO_URI") or CONFIG_MONGO_URI
        if not uri:
            logging.error("MONGO_URI not set (env or config) and no mongo_uri provided.")
            return False

        # Resolve DB/collection
        db_name = db_name or os.environ.get("MONGO_DB_NAME") or MONGO_DB_NAME or "Github"
        collection_name = collection_name or os.environ.get("MONGO_COLLECTION") or MONGO_ACTIVE_COLLECTION or "active_users"

        client = MongoClient(uri,
                             serverSelectionTimeoutMS=15000,
                             tls=True,
                             tlsCAFile=certifi.where())
        # test connection (will raise on failure)
        client.server_info()

        db = client[db_name]
        coll = db[collection_name]

        now = datetime.utcnow()
        # Branch by collection so onboarding behavior is unchanged
        if collection_name == "offboarded_users":
            # Offboarding document shape
            doc = {
                "username": username,
                "email": email,
                # store who removed the user
                "removed_by": invited_by or os.environ.get("INVITED_BY", "offboard_script"),
                "removed_status": invite_status,
                "clickup_task_id": clickup_task_id,
                "clickup_approved_by": clickup_approved_by,
                "offboarded_at": now,
                "updated_at": now,
            }

            # Use a unique key that makes sense for offboarded docs.
            # We can't upsert on github_id (may be None). Use username+email if available.
            query = {}
            if username:
                query["username"] = username
            elif email:
                query["email"] = email
            else:
                # fallback to timestamp-based insert
                coll.insert_one(doc)
                client.close()
                logging.info("Inserted offboard audit entry for username=%s email=%s", username, email)
                return True

            coll.update_one(query, {"$set": doc}, upsert=True)
            client.close()
            logging.info("Upserted offboard entry for username=%s email=%s", username, email)
            return True

        else:
            # Existing onboarding/active users behavior (unchanged)
            # Ensure an index on github_id only for onboarding/active collection
            try:
                coll.create_index([("github_id", 1)], unique=True)
            except Exception:
                pass

        # Set onboarded_at only when invite/accept state indicates onboarding
        onboarded_at = now if invite_status in ("invited", "accepted", "member_existing") else None

        doc = {
            "github_id": int(github_id) if github_id is not None else None,
            "username": username,
            "email": email,
            "invited_by": invited_by or os.environ.get("INVITED_BY", "onboard_script"),
            "invite_status": invite_status,
            "clickup_task_id": clickup_task_id,
            "clickup_approved_by": clickup_approved_by,
            "onboarded_at": onboarded_at,
            "updated_at": now,
            "offboarding_status": False,
        }

        coll.update_one({"github_id": doc["github_id"]}, {"$set": doc}, upsert=True)
        client.close()
        logging.info("Upserted audit entry for github_id=%s username=%s email=%s", doc["github_id"], username, email)
        return True
    except Exception as e:
        logging.exception("Failed to upsert audit entry: %s", e)
        return False

logger = logging.getLogger("utils.github")
def die(msg: str, code: int = 1) -> None:
    logger.error(msg)
    sys.exit(code)


def get_token() -> str:
    token = os.environ.get("ORG_ADMIN_TOKEN")
    if not token:
        die("ORG_ADMIN_TOKEN env var not set", code=2)
    return token


def request_with_retries(method: str, path: str, token: str,
                         json_payload: Optional[dict] = None,
                         params: Optional[dict] = None,
                         max_retries: int = 5,
                         backoff_factor: float = 1.0) -> requests.Response:
    """
    Make an HTTP request with retries for transient failures.
    Retries on network errors and on 429/502/503/504.
    """
    url = f"{API_BASE}{path}"
    headers = HEADERS_BASE.copy()
    headers["Authorization"] = f"token {token}"

    attempt = 0
    while True:
        attempt += 1
        try:
            logger.debug("HTTP %s %s (attempt %d) payload=%s params=%s", method, url, attempt,
                         json_payload if json_payload else "-", params if params else "-")
            resp = requests.request(method, url, headers=headers, json=json_payload, params=params, timeout=30)
        except requests.RequestException as e:
            logger.warning("Network error on attempt %d: %s", attempt, e)
            if attempt >= max_retries:
                logger.exception("Max retries reached for %s %s", method, url)
                raise
            wait = backoff_factor * (2 ** (attempt - 1))
            logger.info("Retrying after %.1fs...", wait)
            time.sleep(wait)
            continue

        # If response is OK-ish, return it
        if resp.status_code < 400:
            logger.debug("HTTP success %s %s -> %s", method, url, resp.status_code)
            return resp

        # Retry on transient server errors / rate limits
        if resp.status_code in (429, 502, 503, 504):
            logger.warning("Transient HTTP %d on attempt %d for %s %s", resp.status_code, attempt, method, url)
            if attempt >= max_retries:
                logger.error("Max retries reached with status %d; returning response", resp.status_code)
                return resp
            # If rate-limited, prefer X-RateLimit-Reset if present
            reset = resp.headers.get("X-RateLimit-Reset")
            if reset:
                try:
                    reset_ts = int(reset)
                    wait = max(0, reset_ts - int(time.time())) + 1
                    logger.info("Rate-limited. Waiting until reset in %ds", wait)
                    time.sleep(wait)
                except Exception:
                    wait = backoff_factor * (2 ** (attempt - 1))
                    logger.info("Waiting %.1fs (backoff)", wait)
                    time.sleep(wait)
            else:
                wait = backoff_factor * (2 ** (attempt - 1))
                logger.info("Waiting %.1fs (backoff)", wait)
                time.sleep(wait)
            continue

        # For other 4xx/5xx, return response for caller to handle/log
        logger.debug("HTTP non-retryable status %d for %s %s", resp.status_code, method, url)
        return resp