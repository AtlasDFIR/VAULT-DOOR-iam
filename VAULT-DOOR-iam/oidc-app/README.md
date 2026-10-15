# OIDC Test App

Local Flask app that signs users in through Okta using the OpenID Connect (OIDC) authorization code flow with PKCE (Proof Key for Code Exchange), then displays every claim in the returned tokens with a plain-language explanation.

Full flow, controls, and test results: [docs/01-oidc-walkthrough.md](../docs/01-oidc-walkthrough.md)

## Run it

From the repository root in Git Bash:

```
py -m venv .venv
source .venv/Scripts/activate
pip install -r oidc-app/requirements.txt
py oidc-app/app.py
```

Then open `http://localhost:5000`. The app reads its settings from `.env` at the repository root (see `.env.example`).

## Test it offline

```
py oidc-app/tests/test_flow.py
```

Runs the whole flow against a simulated Okta org with its own signing key: PKCE, state, nonce validation, group-based denial, token handling, and sign-out. No Okta connection needed.

## Pages

| Path | Purpose |
| --- | --- |
| `/` | Entry terminal, or a summary of the signed-in user |
| `/login` | Starts the flow and redirects to Okta |
| `/authorization-code/callback` | Receives the code, exchanges it, verifies the ID token |
| `/tokens` | Token inspector: decoded headers and claims, tokens truncated |
| `/logout` | Ends the app session and the Okta session |
