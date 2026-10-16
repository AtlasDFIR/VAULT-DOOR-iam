# Lab Environment

Record of how the lab is set up, no confidential Vault-Tec secrets here. 

## Identity provider

|Item|Value|
|-|-|
|Platform|Okta Integrator Free Plan (Okta Identity Engine)|
|Org created|2026-10-15|
|Admin model|One super admin account used for administration only; all testing done as test users|

Note: Integrator Free Plan orgs expire after 90 consecutive days of inactivity, someone keep the coffee running.

## Groups

|Group|Purpose|Assigned to|
|-|-|-|
|`Vault101-Residents`|Users allowed into the lab apps|OIDC app, SAML app|
|`Vault101-Security`|Privileged users held to a stricter sign-on policy|MFA sign-on policy|

## Test users

|Name|Username|Groups|Expected result|
|-|-|-|-|
|Morgan Vale|`hbass2+overseer@wgu.edu`|Residents, Security|Access granted, MFA always required|
|Jesse Dunn|`hbass2+resident@wgu.edu`|Residents|Access granted|
|Riley Crane|`hbass2+drifter@wgu.edu`|None|Access denied|

Test users use plus addressing so each has a unique, deliverable email address without separate mailboxes.

## Workstation

|Item|Value|
|-|-|
|OS|Windows 11 Home|
|Terminal|Git Bash|
|Python|*3.14.3*|
|WSL|*3.0.3.0*|
|Docker|*29.8.2, build 7fc2dff*|

## Setup log

|Date|Change|
|-|-|
|2026-10-15|Created Okta org, two groups, three test users|
|2026-10-15|Installed Docker Desktop (per-user mode, WSL 2 backend)|
|2026-10-16|Created VAULT-DOOR Access policy|
|2026-10-16|Ran lifecycle tests|



