# VAULT-DOOR-iam

Hands-on identity and access management (IAM) lab built on Okta. I set up a working single sign-on (SSO) environment from scratch, integrated a test application over OpenID Connect (OIDC) and a second over Security Assertion Markup Language (SAML), and enforced group-based access and multi-factor authentication (MFA) policy on top of both.

I work as an incident response analyst in a federal Security Operations Center (SOC). Most of the incidents I handle start with an identity: a phished credential, a suspicious sign-in, an account that had more access than it needed. This project is the other side of that work. Instead of investigating what happens when access controls fail, I'm building and testing the controls to get some practice! :)

## What this lab covers

| Area | What I built | Status |
| --- | --- | --- |
| Directory | Okta org with role-based groups and test users | Done |
| OIDC | Local web app using the authorization code flow with PKCE (Proof Key for Code Exchange), with every token claim documented | Done |
| SAML | Containerized service provider (SP) trusting Okta as the identity provider (IdP), with a full assertion walkthrough | Part 3 |
| Access policy | Group-based app assignment, MFA sign-on policy, and a tested deny case | Part 4 |
| Compliance mapping | Controls mapped to NIST SP 800-53 Access Control (AC) and Identification and Authentication (IA) families | Part 4 |

## Lab directory

Every access decision in this lab is made by group, never by individual user.

| Group | Purpose |
| --- | --- |
| `Vault101-Residents` | Users allowed into the lab apps |
| `Vault101-Security` | Privileged users held to a stricter sign-on policy |

| Test user | Groups | Role in testing |
| --- | --- | --- |
| Morgan Vale | Residents, Security | Privileged user |
| Jesse Dunn | Residents | Standard user |
| Riley Crane | None | Negative test: should be denied everywhere |

The Okta super admin account is used for administration only. All app testing runs through the test users above.

## Repository layout

```
VAULT-DOOR-iam/
├── docs/          Lab notes and protocol walkthroughs
├── evidence/      Redacted screenshots, organized by part
├── oidc-app/      OIDC test application (Part 2)
├── saml-sp/       SAML service provider in Docker (Part 3)
└── .env.example   Configuration template; real values live in an untracked .env
```

## Secrets handling

No credentials, client secrets, API tokens, or private keys are committed to this repository. Configuration is read from a local `.env` file that `.gitignore` excludes, and `.env.example` documents the expected variables with placeholder values. Screenshots in `evidence/` are reviewed and redacted before commit, no Enclave spies allowed!

## Progress

- [x] Part 1: Okta org, groups, test users, Docker environment, repository scaffold
- [x] Part 2: OIDC integration
- [ ] Part 3: SAML integration
- [ ] Part 4: Access policy, MFA, and NIST SP 800-53 mapping
