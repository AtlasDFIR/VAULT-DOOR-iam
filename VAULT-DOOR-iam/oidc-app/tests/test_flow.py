"""Offline test of the OIDC flow against a simulated Okta org.

Generates its own RSA signing key, fakes Okta's metadata and token endpoint,
and checks PKCE, state, nonce, group-based denial, token handling, and logout
without touching a real Okta org.

Run from the repository root:  py oidc-app/tests/test_flow.py
"""
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

from joserfc import jwt
from joserfc.jwk import RSAKey

APP_DIR = Path(__file__).resolve().parent.parent
ORG = "https://integrator-0000000.okta.com"
CLIENT_ID = "0oaTESTCLIENTID"

os.environ.update({
    "OKTA_ORG_URL": ORG,
    "OIDC_CLIENT_ID": CLIENT_ID,
    "OIDC_CLIENT_SECRET": "test-secret",
    "FLASK_SECRET_KEY": "x" * 64,
})
sys.path.insert(0, str(APP_DIR))
import app as vault  # noqa: E402

key = RSAKey.generate_key(2048, parameters={"kid": "test-kid", "use": "sig", "alg": "RS256"})
vault.oauth.okta.server_metadata.update({
    "_loaded_at": time.time(),
    "issuer": ORG,
    "authorization_endpoint": f"{ORG}/oauth2/v1/authorize",
    "token_endpoint": f"{ORG}/oauth2/v1/token",
    "end_session_endpoint": f"{ORG}/oauth2/v1/logout",
    "jwks": {"keys": [key.as_dict(private=False)]},
    "id_token_signing_alg_values_supported": ["RS256"],
})

client = vault.app.test_client()
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


r = client.get("/")
check("home page renders signed out", r.status_code == 200 and b"Enter the Vault" in r.data)

r = client.get("/login")
loc = r.headers.get("Location", "")
q = parse_qs(urlparse(loc).query)
check("login redirects to Okta authorize endpoint", r.status_code == 302 and loc.startswith(f"{ORG}/oauth2/v1/authorize"), loc)
check("PKCE S256 challenge sent", q.get("code_challenge_method") == ["S256"] and q.get("code_challenge"))
check("scopes include openid groups", "groups" in q.get("scope", [""])[0] and "openid" in q.get("scope", [""])[0])
check("state and nonce present", q.get("state") and q.get("nonce"))
check("redirect_uri correct", q.get("redirect_uri") == ["http://localhost:5000/authorization-code/callback"])
state, nonce = q["state"][0], q["nonce"][0]

r = client.get("/authorization-code/callback?error=access_denied&error_description=User+is+not+assigned+to+the+client+application.")
check("deny case returns 403 page", r.status_code == 403 and b"Access denied" in r.data and b"not assigned" in r.data)

now = int(time.time())
claims = {
    "sub": "00uTESTUSER", "name": "Jesse Dunn", "email": "hbass2+resident@wgu.edu",
    "ver": 1, "iss": ORG, "aud": CLIENT_ID, "iat": now, "exp": now + 3600,
    "jti": "ID.test", "amr": ["pwd"], "idp": "00oTESTIDP", "nonce": nonce,
    "preferred_username": "hbass2+resident@wgu.edu", "auth_time": now,
    "groups": ["Vault101-Residents"],
}
id_token = jwt.encode({"alg": "RS256", "kid": "test-kid"}, claims, key)
access_token = jwt.encode({"alg": "RS256", "kid": "test-kid"}, {"ver": 1, "iss": ORG, "aud": ORG, "iat": now, "exp": now + 3600, "cid": CLIENT_ID, "uid": "00uTESTUSER", "scp": ["openid", "profile", "email", "groups"], "sub": "hbass2+resident@wgu.edu"}, key)
fake_token = {"access_token": access_token, "id_token": id_token, "token_type": "Bearer", "expires_in": 3600, "scope": "openid profile email groups"}

with patch.object(vault.oauth.okta, "fetch_access_token", return_value=dict(fake_token)) as fetch:
    r = client.get(f"/authorization-code/callback?code=ABCDEFGH123&state={state}")
    sent = fetch.call_args.kwargs if fetch.call_args else {}
check("callback redirects home after token exchange", r.status_code == 302, r.status_code)
check("code_verifier sent in token exchange (PKCE)", bool(sent.get("code_verifier")), sent.keys())

r = client.get("/")
check("signed-in home shows user and group", b"Jesse Dunn" in r.data and b"Vault101-Residents" in r.data)

r = client.get("/tokens")
check("token inspector renders claims", r.status_code == 200 and b"Payload" in r.data and b"nonce" in r.data)
check("full ID token never shown", id_token.encode() not in r.data and b"[truncated]" in r.data)
check("access token decoded", b"scp" in r.data and b"cid" in r.data)

# Tampered token must be rejected
r2 = vault.app.test_client()
loc2 = r2.get("/login").headers["Location"]
q2 = parse_qs(urlparse(loc2).query)
bad = dict(claims, nonce="wrong-nonce")
bad_token = dict(fake_token, id_token=jwt.encode({"alg": "RS256", "kid": "test-kid"}, bad, key))
rejected = False
with patch.object(vault.oauth.okta, "fetch_access_token", return_value=bad_token):
    try:
        resp = r2.get(f"/authorization-code/callback?code=X&state={q2['state'][0]}")
        rejected = resp.status_code == 401 and b"token_validation_failed" in resp.data
    except Exception:
        rejected = True
check("wrong nonce rejected", rejected)

r = client.get("/logout")
loc = r.headers.get("Location", "")
lq = parse_qs(urlparse(loc).query)
check("logout redirects to Okta end_session", loc.startswith(f"{ORG}/oauth2/v1/logout") and lq.get("post_logout_redirect_uri") == ["http://localhost:5000/"] and lq.get("id_token_hint"))
r = client.get("/tokens")
check("session cleared after logout", r.status_code == 302)

passed = sum(ok for _, ok in results)
print(f"\n{passed}/{len(results)} checks passed")
sys.exit(0 if passed == len(results) else 1)
