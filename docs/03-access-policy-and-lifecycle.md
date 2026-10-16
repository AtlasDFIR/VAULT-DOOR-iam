# Access Policy and Lifecycle

How the lab decides who gets in and how hard they have to prove it, and what happens to access when a user's role changes or they leave.

## Policy design

Both VAULT-DOOR apps share one Okta app sign-in policy, `VAULT-DOOR Access`. Okta evaluates the rules top to bottom and applies the first one that matches.

|Priority|Rule|Applies to|Requirement|Re-authentication|
|-|-|-|-|-|
|1|Overseer clearance|`Vault101-Security`|Phishing-resistant possession factor with PIN or biometric verification|Every time the user signs in to an app|
|2|Resident access|`Vault101-Residents`|Phishing-resistant possession factor with PIN or biometric verification|Only after 2 hours since the last sign-in|
|Last|Catch-all|Everyone else|Access denied|Not applicable|

The design follows three principles:

* **Privileged users prove themselves more often.** A stolen session for a Security group member is worth more to an attacker, so that session is never reused across apps.
* **Standard users get single sign-on.** Once a resident authenticates, they can move between both apps for two hours without another prompt.
* **Default deny.** Group assignment already keeps unassigned users out. The catch-all deny rule is a second layer, so a misconfigured assignment doesn't silently grant access.

## Test results

|Test|What I did|Expected|Observed|
|-|-|-|-|
|Resident SSO|Jesse signs in to the OIDC app, then opens the SAML app in the same window|SAML app opens with no new prompt|*SAML session saw no prompt*|
|Overseer re-authentication|Morgan signs in to the OIDC app, then opens the SAML app in the same window|Okta prompts for the passkey again|*see finding below*|
|Mover|Remove Morgan from `Vault101-Security`, sign in fresh|`groups` shows only Residents, no re-prompt between apps|*Groups only showed 'Residents'*|
|Leaver, new sign-in|Suspend Jesse, then try to sign in|Okta refuses|*User denied access*|
|Leaver, existing session|Suspend Jesse while already signed in to an app|*see notes below*|*Session was unaware of update*|

## Lifecycle finding: suspending the user doesn't end existing app sessions

*Initial testing demonstrated that opening the SAML within a 10-second grace period of successful authentication within the OIDC terminal requires no prompt for reverification. Follow-up testing implemented a 30-second pause, and then successful asked for reverification when trying to authenticate with the SAML application.*

Disabling an account at the identity provider (IdP) stops new sign-ins immediately. It does not reach into an app and end a session the app already created. Both VAULT-DOOR apps keep their own session after sign-in and never check back with Okta, so a suspended user can keep using an app until that session ends on its own.

Real offboarding has to close that gap. The usual controls:

|Control|What it does|
|-|-|
|Short app session lifetimes|Limits how long a stale session stays usable|
|Token expiry enforced by the app|The OIDC access token expires in one hour; an app that checks it cuts access then|
|Single logout or Universal Logout|Okta tells each app to end the user's session|
|SCIM (System for Cross-domain Identity Management) deprovisioning|Okta deactivates the user's account inside the app itself|
|Clearing the user's Okta sessions|Prevents silent SSO into any further apps|

This lab uses **Suspend** so the test is reversible. A real leaver would be **deactivated**, which also removes their app assignments.

## System Log review

Okta records every step of these tests. The event types worth knowing:

|Event|Meaning|
|-|-|
|`user.session.start`|User started an Okta session|
|`policy.evaluate\_sign\_on`|Okta evaluated an app sign-in policy, including which rule matched|
|`user.authentication.sso`|User was signed in to an app|
|`group.user\_membership.remove` / `add`|User left or joined a group|
|`user.lifecycle.suspend` / `unsuspend`|Account was suspended or restored|

These are the events I would pull first in an investigation into a suspicious sign-in or an access complaint.

## Notes

- The session was unaware of the update to the user, and thus opened and displayed all information when I clicked into *Inspect tokens*. However, upon attempting to sign back in, then it was clear that the update had gone through and the user was now deactivated.

