# SAML Service Provider

Containerized Flask app that trusts Okta as its SAML (Security Assertion Markup Language) 2.0 identity provider (IdP). It starts SP-initiated sign-in, validates the signed assertion Okta posts back, and shows the decoded assertion with every check it passed.

Full flow, checks, OIDC comparison, and test results: [docs/02-saml-walkthrough.md](../docs/02-saml-walkthrough.md)

## Run it

From the repository root, with Docker Desktop running:

```
docker compose up --build
```

Then open `http://localhost:8000`. Settings come from `.env` at the repository root: `SAML_IDP_METADATA_URL` and `FLASK_SECRET_KEY`.

## Test it offline

```
docker compose run --rm saml-sp python tests/test_flow.py
```

Signs assertions with a throwaway certificate and confirms the app accepts a valid one and rejects tampered, unsigned, expired, wrong-audience, wrong-destination, and unsolicited responses. No Okta connection needed.

## Pages

| Path | Purpose |
| --- | --- |
| `/` | Entry terminal, or a summary of the signed-in user |
| `/saml/login` | Builds an AuthnRequest and redirects to Okta |
| `/saml/acs` | Assertion Consumer Service: receives and validates Okta's response |
| `/assertion` | Assertion inspector: every check, attribute, and the raw XML |
| `/saml/metadata` | This SP's own metadata document |
| `/logout` | Ends this app's session |
