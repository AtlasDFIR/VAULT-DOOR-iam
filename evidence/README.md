# Evidence

Screenshots proving each part of the lab works, organized by part.

## Enclave Spies Beware!

- [ ] No passwords, client secrets, API tokens, or session cookies are visible
- [ ] No full tokens visible (ID tokens and access tokens are truncated before capture)
- [ ] Console tabs, bookmarks, and communications cropped out
- [ ] Nothing from my employer's environment anywhere in the image

## Index

| Part | File | Shows |
| --- | --- | --- |
| 1 | `part1/01-people.png` | Three test users, all Active |
| 1 | `part1/02-residents-group.png` | Vault101-Residents membership |
| 1 | `part1/03-security-group.png` | Vault101-Security membership |
| 1 | `part1/04-docker-hello-world.png` | Docker running the hello-world container |
| 2 | `part2/01-oidc-app-settings.png` | OIDC app General tab: grant type, PKCE, redirect URIs (client secret hidden) |
| 2 | `part2/02-oidc-assignments.png` | App assigned to Vault101-Residents only |
| 2 | `part2/03-signed-in-resident.png` | Jesse Dunn signed in, groups shown |
| 2 | `part2/04-token-inspector.png` | Decoded ID token claims, token truncated |
| 2 | `part2/05-denied-drifter.png` | Riley Crane refused access |
| 2 | `part2/06-audit-log.png` | Terminal audit lines for success, denial, and sign-out |
| 2 | `part2/07-offline-test.png` | Offline flow test, 16/16 passing |
| 3 | `part3/01-saml-app-settings.png` | SAML settings: ACS URL, audience, NameID format, attribute statements |
| 3 | `part3/02-saml-assignments.png` | App assigned to Vault101-Residents only |
| 3 | `part3/03-offline-test.png` | Offline SAML test in the container, 16/16 passing |
| 3 | `part3/04-signed-in-resident.png` | Jesse Dunn signed in over SAML, groups shown |
| 3 | `part3/05-assertion-inspector.png` | Checks passed and attributes, signature truncated |
| 3 | `part3/06-saml-tracer.png` | SAML-tracer capture of the AuthnRequest and signed response |
| 3 | `part3/07-denied-drifter.png` | Riley Crane refused by Okta |
| 4 | `part4/01-policy-rules.png` | VAULT-DOOR Access rules in priority order |
| 4 | `part4/02-policy-apps.png` | Both VAULT-DOOR apps assigned to the policy |
| 4 | `part4/03-overseer-reprompt.png` | Morgan prompted again when opening the second app |
| 4 | `part4/04-mover-groups.png` | Morgan's groups after removal from Vault101-Security |
| 4 | `part4/05-leaver-session.png` | Suspended user still inside an existing app session |
| 4 | `part4/06-leaver-denied.png` | Suspended user refused on a new sign-in |
| 4 | `part4/07-system-log.png` | System Log events from the Part 4 tests |