"""VAULT-DOOR OIDC test app.

A small Flask web app that signs users in through Okta using the OpenID Connect
(OIDC) authorization code flow with PKCE (Proof Key for Code Exchange), then
shows every claim in the tokens Okta returns.

Run from the repository root:  py oidc-app/app.py
"""

import base64
import json
import logging
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for

# The .env file lives at the repository root, one level above this folder.
REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")

REQUIRED = ["OKTA_ORG_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "FLASK_SECRET_KEY"]
missing = [name for name in REQUIRED if not os.getenv(name) or os.getenv(name) == "replace-me"]
if missing:
    sys.exit(
        "Missing settings in .env: " + ", ".join(missing)
        + "\nCopy .env.example to .env at the repository root and fill these in."
    )

ORG_URL = os.environ["OKTA_ORG_URL"].rstrip("/")
# Okta's org authorization server. Its issuer is the org URL itself.
ISSUER = os.getenv("OKTA_ISSUER", ORG_URL).rstrip("/")
REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "http://localhost:5000/authorization-code/callback")
POST_LOGOUT_REDIRECT_URI = os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/")
SCOPES = "openid profile email groups"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
audit = logging.getLogger("vault-door.audit")

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

oauth = OAuth(app)
oauth.register(
    name="okta",
    client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={"scope": SCOPES, "code_challenge_method": "S256"},
)

# Tokens are kept server side, keyed by a random session id, so they never sit
# in the browser cookie. In-memory only: restarting the app signs everyone out.
TOKEN_STORE = {}

# Plain-language meaning of each claim, shown on the token inspector page.
CLAIM_NOTES = {
    "iss": "Issuer. Who created the token. Must match your Okta org URL exactly.",
    "sub": "Subject. Okta's permanent, unique ID for this user. Apps should key on this, not on email.",
    "aud": "Audience. Who the token is for. In an ID token this must be this app's client ID.",
    "iat": "Issued at. When Okta created the token.",
    "exp": "Expires. After this time the token must be rejected.",
    "auth_time": "When the user actually authenticated, which can be earlier than iat if Okta reused an existing session.",
    "nonce": "Random value this app sent at login. Matching it proves the token was minted for this exact sign-in and blocks replay.",
    "amr": "Authentication methods used, such as pwd (password), mfa, or otp. Useful evidence that MFA happened.",
    "idp": "ID of the identity provider that authenticated the user. Here, the Okta org itself.",
    "at_hash": "Hash of the access token, binding the two tokens together so one can't be swapped for another.",
    "name": "User's full name, from the profile scope.",
    "email": "User's email, from the email scope.",
    "email_verified": "Whether Okta has verified this email address.",
    "preferred_username": "The user's Okta username.",
    "groups": "Okta groups the user belongs to, filtered by the app's groups claim setting.",
    "ver": "Token format version.",
    "jti": "Unique ID for this token, useful for detecting replay and correlating logs.",
    "cid": "Client ID of the app the access token was issued to.",
    "uid": "Okta user ID (same value as sub).",
    "scp": "Scopes this access token grants.",
    "locale": "User's language and region setting.",
    "zoneinfo": "User's time zone.",
    "given_name": "User's first name.",
    "family_name": "User's last name.",
    "updated_at": "When the user's profile last changed.",
}
TIME_CLAIMS = {"iat", "exp", "auth_time", "updated_at"}


def decode_jwt_part(token, index):
    """Decode the header (0) or payload (1) of a JWT for display only.

    This does not verify anything. The ID token was already verified by
    Authlib (signature, issuer, audience, expiry, nonce) during sign-in.
    """
    part = token.split(".")[index]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def claim_rows(claims):
    rows = []
    for key, value in claims.items():
        shown = value
        if key in TIME_CLAIMS and isinstance(value, (int, float)):
            stamp = datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            shown = f"{value}  ({stamp})"
        elif isinstance(value, (list, dict)):
            shown = json.dumps(value)
        rows.append({"name": key, "value": shown, "note": CLAIM_NOTES.get(key, "")})
    return rows


def truncate(token, keep=24):
    return token[:keep] + "...[truncated]" if token and len(token) > keep else token


def current_tokens():
    sid = session.get("sid")
    return TOKEN_STORE.get(sid) if sid else None


@app.route("/")
def index():
    tokens = current_tokens()
    user = tokens["claims"] if tokens else None
    return render_template("index.html", user=user)


@app.route("/login")
def login():
    audit.info("AUTH START redirecting to Okta, scopes=%s pkce=S256", SCOPES)
    return oauth.okta.authorize_redirect(REDIRECT_URI)


@app.route("/authorization-code/callback")
def callback():
    if "error" in request.args:
        error = request.args.get("error")
        description = request.args.get("error_description", "")
        audit.warning("AUTH DENIED error=%s description=%s", error, description)
        return render_template("denied.html", error=error, description=description), 403

    code = request.args.get("code", "")
    audit.info("AUTH CODE received code=%s", truncate(code, 8))

    # Exchanges the code (plus the PKCE code_verifier) for tokens, then verifies
    # the ID token's signature, issuer, audience, expiry, and nonce.
    try:
        token = oauth.okta.authorize_access_token()
    except Exception as exc:  # signature, issuer, audience, expiry, nonce, or state failure
        audit.warning("AUTH REJECTED token validation failed: %s", exc)
        return render_template(
            "denied.html",
            error="token_validation_failed",
            description=f"This app refused the tokens it received: {exc}",
        ), 401
    claims = token["userinfo"]

    sid = secrets.token_urlsafe(32)
    TOKEN_STORE[sid] = {
        "id_token": token["id_token"],
        "access_token": token.get("access_token", ""),
        "claims": dict(claims),
        "scope": token.get("scope", ""),
        "expires_in": token.get("expires_in"),
        "signed_in_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    session.clear()
    session["sid"] = sid

    audit.info(
        "AUTH SUCCESS sub=%s user=%s groups=%s amr=%s",
        claims.get("sub"), claims.get("preferred_username"),
        claims.get("groups"), claims.get("amr"),
    )
    return redirect(url_for("index"))


@app.route("/tokens")
def tokens():
    stored = current_tokens()
    if not stored:
        return redirect(url_for("index"))

    id_token = stored["id_token"]
    access_token = stored["access_token"]
    access = None
    if access_token.count(".") == 2:
        access = {
            "header": decode_jwt_part(access_token, 0),
            "rows": claim_rows(decode_jwt_part(access_token, 1)),
            "preview": truncate(access_token),
        }

    return render_template(
        "tokens.html",
        id_header=decode_jwt_part(id_token, 0),
        id_rows=claim_rows(decode_jwt_part(id_token, 1)),
        id_preview=truncate(id_token),
        access=access,
        scope=stored["scope"],
        expires_in=stored["expires_in"],
        signed_in_at=stored["signed_in_at"],
    )


@app.route("/logout")
def logout():
    stored = current_tokens()
    sid = session.get("sid")
    session.clear()
    if not stored:
        return redirect(url_for("index"))

    TOKEN_STORE.pop(sid, None)
    audit.info("AUTH LOGOUT sub=%s", stored["claims"].get("sub"))

    # RP-initiated logout ends the Okta session too, not just this app's session.
    end_session = oauth.okta.load_server_metadata().get("end_session_endpoint")
    if not end_session:
        return redirect(url_for("index"))
    params = {"id_token_hint": stored["id_token"], "post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI}
    return redirect(f"{end_session}?{urlencode(params)}")


if __name__ == "__main__":
    print(f"\nVAULT-DOOR OIDC app running. Open http://localhost:5000 in your browser.")
    print("Press Ctrl + C in this window to stop it.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
