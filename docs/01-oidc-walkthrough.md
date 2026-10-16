# OIDC Walkthrough

How the VAULT-DOOR test app signs a user in through Okta with OpenID Connect (OIDC), what each step proves, and what I observed testing it.

## The flow

The app uses the authorization code flow with PKCE (Proof Key for Code Exchange). The browser only ever carries a short-lived, single-use code. Tokens travel over a direct back-channel request between the app and Okta.

```mermaid
sequenceDiagram
    autonumber
    participant U as User's browser
    participant A as VAULT-DOOR app (localhost:5000)
    participant O as Okta (org authorization server)

    U->>A: Click "Enter the Vault"
    A->>A: Generate state, nonce, and PKCE code_verifier
    A->>U: Redirect to Okta /authorize with code_challenge (S256), state, nonce
    U->>O: Authorization request
    O->>U: Sign-in page
    U->>O: Username, password, and any required factor
    O->>O: Is this user assigned to the app (via Vault101-Residents)?
    O->>U: Redirect to /authorization-code/callback with code and state
    U->>A: Callback with code and state
    A->>A: Check state matches what was sent
    A->>O: POST /token with code, code_verifier, client credentials
    O->>O: Hash code_verifier, compare to code_challenge
    O->>A: ID token and access token
    A->>A: Verify ID token signature (JWKS), iss, aud, exp, nonce
    A->>U: Signed in
```

## What each control prevents

|Control|Where it's checked|Attack it stops|
|-|-|-|
|`state`|App, on callback|Cross-site request forgery (CSRF) that logs a victim into an attacker's session|
|PKCE `code_verifier` / `code_challenge`|Okta, at the token endpoint|A stolen authorization code being redeemed by anyone other than the app that requested it|
|`nonce`|App, inside the ID token|Replay of an old or stolen ID token|
|ID token signature|App, against Okta's published keys (JWKS)|Forged or modified tokens|
|`iss` and `aud`|App|Tokens minted by another issuer or for another app being accepted here|
|`exp`|App|Use of expired tokens|
|Client secret|Okta, at the token endpoint|An unregistered client exchanging codes|
|Group-based assignment|Okta, before issuing a code|Users outside `Vault101-Residents` reaching the app at all|

## Okta configuration

|Setting|Value|
|-|-|
|Application type|OIDC, Web Application|
|Grant type|Authorization Code|
|PKCE|Required|
|Sign-in redirect URI|`http://localhost:5000/authorization-code/callback`|
|Sign-out redirect URI|`http://localhost:5000/`|
|Assignment|`Vault101-Residents` group only|
|Groups claim|Filter, name `groups`, starts with `Vault101`|
|Scopes requested|`openid profile email groups`|

## Test results

|Test|User|Expected|Observed|
|-|-|-|-|
|Assigned user signs in|Jesse Dunn|Access granted, `groups` contains `Vault101-Residents`|*Successful authentication*|
|Privileged user signs in|Morgan Vale|Access granted, `groups` contains both Vault101 groups|*Successful authentication*|
|Unassigned user signs in|Riley Crane|Okta refuses, app shows access denied|*Unsuccessful authentication, user not assigned*|
|Sign out|Any|App and Okta sessions both end|*Successful sign off*|
|Offline flow test|None|`py oidc-app/tests/test_flow.py` reports 16/16|*16/16 reports observed*|

## Notes

- The `amr` claim came back as `["pop"]` (proof of possession). For Jesse's sign-in on 2026-10-16, the Okta System Log shows Windows Hello as the only authenticator, with no password, so that token reflects a passwordless, phishing-resistant sign-in. The org's default policy only offered Okta Verify and Passkey as second factors, which ruled out weaker methods like email codes.

