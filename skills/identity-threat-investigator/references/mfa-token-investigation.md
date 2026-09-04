# MFA and Token Investigation

## Model

Distinguish:

- primary credential validation;
- fresh MFA or phishing-resistant authentication;
- authentication satisfied by an existing claim;
- Primary Refresh Token;
- refresh token;
- access token;
- application-issued session cookie.

MFA protects an authentication step. It does not prove that every later use of the resulting session is legitimate.

## Investigation sequence

1. Identify the first supported authentication event and the authentication requirement.
2. Determine whether MFA was fresh, previously satisfied, skipped, not applied, or unknown.
3. Compare Conditional Access outcomes with the expected policy set.
4. Trace related interactive and non-interactive activity.
5. Pivot on supported request, session, sign-in activity, and unique-token identifiers.
6. Examine downstream Graph, Exchange, SharePoint, OneDrive, Teams, and cloud application operations.
7. Look for persistence after the suspected event:
   - authentication-method changes;
   - device registration or join;
   - password reset or security-info change;
   - mailbox forwarding or inbox rules;
   - OAuth consent or app-role grants;
   - app owner, secret, certificate, or federated-credential changes;
   - directory role or group changes.
8. Identify all affected identities, applications, resources, devices, and tenants.

## MFA abuse and bypass families

- adversary-in-the-middle interception;
- session-cookie theft and reuse;
- refresh-token theft or misuse;
- MFA request generation or fatigue;
- telephony and recovery-channel abuse;
- help-desk or self-service reset abuse;
- authentication-method registration by an attacker;
- device registration used to satisfy policy;
- legacy authentication or policy exclusions;
- federation or token-issuer compromise;
- application consent and workload-identity abuse.

Describe these at defensive analytic depth. Do not provide deployment instructions, phishing procedures, credential capture steps, or evasion guidance.

## Evidence that strengthens a token/session hypothesis

- token-satisfied authentication from a context not supported by the baseline;
- non-interactive activity inconsistent with preceding interactive authentication;
- simultaneous or overlapping resource use from incompatible contexts;
- token-specific risk detections corroborated by downstream actions;
- new persistence shortly after the suspicious session;
- use of sensitive resources or privileges;
- identifiers linking issuance and downstream operation;
- endpoint or identity detections indicating attempted token access.

## Evidence limits

Logs usually cannot prove:

- who physically operated a device;
- precise physical location from an IP;
- replay when the attacker uses the victim's device, network, or browser context;
- application activity hidden behind an app-issued cookie;
- activity outside retention or uncollected providers;
- theft merely because a provider emitted a low- or medium-risk token anomaly.

State these limitations in the report.

## Containment caveats

Password reset, session revocation, account disablement, device disablement, authentication-method removal, and third-party application session revocation affect different credential and session layers. No single action should be described as universal eviction.

Response proposals must:

- preserve evidence first;
- identify home and resource tenant implications;
- identify CAE and non-CAE gaps;
- identify application sessions outside Entra control;
- show privileged and emergency-access impact;
- identify reversible and destructive actions;
- require explicit human authorization.
