import hashlib
import hmac
import os
import time
from urllib.parse import urlencode

import httpx
import jwt

from app.auth import SECRET_KEY

SLACK_CLIENT_ID = os.environ.get("SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.environ.get("SLACK_CLIENT_SECRET", "")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")

# Minimum viable bot scopes for what app/slack_bot.py + the /slack/commands
# and /slack/interactions handlers actually do: post messages, read
# workspace/user identity for auth.test, receive slash commands, and (
# chat:write.public) post critical-incident alerts into a second,
# admin-chosen channel without needing the bot to be invited into it first.
SLACK_BOT_SCOPES = "chat:write,chat:write.public,commands,channels:read,incoming-webhook"

_STATE_ALG = "HS256"
_STATE_TTL_SECONDS = 600  # 10 minutes - long enough to click through Slack's
# consent screen, short enough that a leaked/replayed state token is useless
# soon after. Reuses the same JWT_SECRET_KEY as login tokens (app/auth.py)
# rather than adding a second secret to configure, but is namespaced with
# its own "purpose" claim so a Slack state token can never be replayed as a
# login token or vice versa - decode_access_token() (app/auth.py) doesn't
# check "purpose", but nothing there accepts a token missing the claims it
# expects (sub/exp) either, so cross-use fails closed either direction.


def sign_oauth_state(organization_id: int, user_id: int) -> str:
    """A signed, tamper-proof, short-lived token carrying which org/user
    initiated the OAuth install - Slack's redirect back to our callback is a
    plain unauthenticated browser GET, so this is the only way to know which
    SentraOps organization the resulting bot token belongs to, without
    standing up a separate "pending install" DB table."""
    payload = {"purpose": "slack_oauth", "org_id": organization_id, "user_id": user_id, "exp": int(time.time()) + _STATE_TTL_SECONDS}
    return jwt.encode(payload, SECRET_KEY, algorithm=_STATE_ALG)


def verify_oauth_state(token: str) -> dict:
    """Raises jwt.PyJWTError (expired/invalid/tampered) - the caller turns
    that into a 400, same as any other bad callback input."""
    payload = jwt.decode(token, SECRET_KEY, algorithms=[_STATE_ALG])
    if payload.get("purpose") != "slack_oauth":
        raise jwt.InvalidTokenError("not a slack_oauth state token")
    return payload


def build_authorize_url(state: str, redirect_uri: str) -> str:
    params = {
        "client_id": SLACK_CLIENT_ID,
        "scope": SLACK_BOT_SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    return f"https://slack.com/oauth/v2/authorize?{urlencode(params)}"


def exchange_code_for_token(code: str, redirect_uri: str) -> dict:
    """POSTs to Slack's token-exchange endpoint. Returns the parsed JSON
    response as-is (caller checks response["ok"]) rather than raising here -
    a rejected/expired code is an expected, user-facing outcome (the install
    failed), not a 500-worthy exception."""
    response = httpx.post(
        "https://slack.com/api/oauth.v2.access",
        data={
            "client_id": SLACK_CLIENT_ID,
            "client_secret": SLACK_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def verify_slack_signature(timestamp: str, body: bytes, signature: str) -> bool:
    """Per Slack's request-signing spec: v0:{timestamp}:{raw body}, HMAC-SHA256
    with the app's Signing Secret, constant-time compared against the
    X-Slack-Signature header. Every inbound webhook (slash command, button
    click) must pass this before being trusted - it's the only thing standing
    between "any POST to a public URL" and "an org's incident data"."""
    if not SLACK_SIGNING_SECRET:
        return False
    # Slack rejects (and so do we) requests replayed more than 5 minutes old.
    try:
        if abs(time.time() - float(timestamp)) > 60 * 5:
            return False
    except (TypeError, ValueError):
        return False

    basestring = b"v0:" + timestamp.encode() + b":" + body
    computed = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)
