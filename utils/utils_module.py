import os
import logging
import requests
import time
from typing import Optional
import sys

API_BASE = "https://api.github.com"
HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "sc-infra-vpn-butler-onboard-script"
}

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