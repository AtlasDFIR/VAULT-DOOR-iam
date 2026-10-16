# NIST SP 800-53 Rev. 5 Control Mapping

How this lab maps to NIST Special Publication (SP) 800-53 Revision 5 controls, with evidence for each. Status is as honest as I can be: this is a lab, and some controls are only partly met or deliberately out of scope.

| Status | Meaning |
| --- | --- |
| Implemented | The lab enforces it and the evidence shows it working |
| Partial | Part of the control is in place, with a named gap |
| Gap | Not addressed in the lab, with the reason |

## Access Control (AC)

| Control | How the lab addresses it | Evidence | Status |
| --- | --- | --- | --- |
| AC-2 Account Management | Role-based groups, named test accounts, and tested joiner, mover, and leaver changes | `00-lab-environment.md`, Part 4 tests | Implemented |
| AC-3 Access Enforcement | Okta refuses users not assigned through `Vault101-Residents` before issuing any token or assertion | Riley denied in Parts 2 and 3 | Implemented |
| AC-6 Least Privilege | Apps receive only `Vault101` groups through claim and attribute filters, not every group a user holds | Groups claim filter, group attribute statement | Implemented |
| AC-6(2) Non-privileged Access for Nonsecurity Functions | The super admin account is used only for administration; all testing runs as test users | Lab environment record | Implemented |
| AC-12 Session Termination | Sign-out ends app sessions, but suspending a user at Okta does not end an app session already in progress | Part 4 leaver finding | Partial |

## Identification and Authentication (IA)

| Control | How the lab addresses it | Evidence | Status |
| --- | --- | --- | --- |
| IA-2 Identification and Authentication (Organizational Users) | Every user is uniquely identified by Okta (`sub` in OIDC, `NameID` in SAML) | Token and assertion inspectors | Implemented |
| IA-2(1) Multi-factor Authentication to Privileged Accounts | `Vault101-Security` requires a phishing-resistant passkey with PIN or biometric verification | Policy rules, Morgan re-prompt test | Implemented |
| IA-2(2) Multi-factor Authentication to Non-privileged Accounts | `Vault101-Residents` requires the same passkey standard | Policy rules | Implemented |
| IA-2(8) Access to Accounts: Replay Resistant | PKCE, `nonce`, `state`, `InResponseTo`, short assertion windows, and passkeys bound to the origin | Offline tests reject replayed and unsolicited responses | Implemented |
| IA-5(2) Public Key-based Authentication | Passkeys authenticate with a private key held in Windows Hello; the IdP stores only the public key | `amr` of `pop` | Implemented |
| IA-11 Re-authentication | Privileged users must re-authenticate every time they sign in to an app | Morgan re-prompt test | Implemented |

## Audit and Accountability (AU)

| Control | How the lab addresses it | Evidence | Status |
| --- | --- | --- | --- |
| AU-2 Event Logging | Sign-in starts, successes, denials, rejected tokens or assertions, and sign-outs are logged by both apps | App audit log screenshots | Implemented |
| AU-3 Content of Audit Records | Each app log line records the time, event, user identifier, groups, and outcome | App audit log screenshots | Implemented |
| AU-6 Audit Record Review, Analysis, and Reporting | Okta System Log reviewed for policy evaluation, SSO, group, and lifecycle events | System Log screenshot | Implemented |

## System and Communications Protection (SC)

| Control | How the lab addresses it | Evidence | Status |
| --- | --- | --- | --- |
| SC-8 Transmission Confidentiality and Integrity | Traffic to Okta uses HTTPS. The local apps run over plain HTTP on `localhost` only | Redirect and ACS URLs | Partial |
| SC-23 Session Authenticity | `state` and `InResponseTo` bind responses to requests; session cookies are `HttpOnly` and `SameSite=Lax`; tokens and assertions are stored server side | App code, offline tests | Implemented |

## Configuration Management (CM) and System Acquisition (SA)

| Control | How the lab addresses it | Evidence | Status |
| --- | --- | --- | --- |
| CM-7 Least Functionality | The SAML container runs as a non-root user, with a read-only filesystem and no privilege escalation, reachable only from this PC | `docker-compose.yml`, `Dockerfile` | Implemented |
| SA-11 Developer Testing and Evaluation | Offline tests prove each security check rejects the attack it exists to stop | 16/16 OIDC and 16/16 SAML test runs | Implemented |

## Known gaps

| Gap | Why it exists | Production fix |
| --- | --- | --- |
| Plain HTTP between browser and local apps | Lab apps run on `localhost` only | TLS on every app endpoint |
| No automatic session revocation on deprovisioning | Apps don't check back with Okta after sign-in | SCIM deprovisioning, Universal Logout, short session lifetimes |
| No SAML single logout | Requires the app to hold a signing certificate | SP signing keys and SLO configuration |
| Sessions held in memory | Simplicity; a restart signs everyone out | Shared session store such as Redis |
| No periodic access reviews | Three test users don't justify a review cycle | Okta Identity Governance access certifications |
