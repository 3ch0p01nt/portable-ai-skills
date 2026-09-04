# Baselines and Deviations

## Baseline dimensions

Build separate baselines for:

1. Human identity: work hours, applications, resources, devices, authentication, network, geography, failures, and privilege use.
2. Peer group: role, organization, geography, employment type, and expected administrative duties.
3. Workload identity: source infrastructure, credential type, schedule, target APIs, permissions, operation volume, and deployment changes.
4. Device: enrollment, compliance, owners, operating system, browser, network egress, and historical identities.
5. Session: interactive versus non-interactive mix, token-satisfied authentication, concurrent locations, applications, and refresh cadence.
6. Organizational context: travel, remote work, VPN, VDI, migrations, incident response, maintenance, and change windows.

## Quality labels

- `known`: representative evidence supports the baseline.
- `cold_start`: too little history; use peer or workload context and lower confidence.
- `stale`: the baseline predates a material role, device, network, or organization change.
- `unavailable`: the required source is not collected or accessible.
- `unknown`: source status or meaning cannot be established.

Always disclose sample size, time window, retention truncation, and whether the baseline may contain attacker activity.

## Common deviations

- new or rare ASN, country, device, browser, client, application, or resource;
- impossible or atypical travel;
- new authentication method or weaker authentication path;
- unexpected token-satisfied authentication;
- non-interactive activity from a new context;
- Conditional Access unexpectedly not applied;
- new device registration or ownership;
- unusual consent, app credential, owner, or federated credential;
- first-time or off-pattern privilege use;
- mailbox rule, sharing, file-access, or Graph-operation burst;
- workload identity source, target, schedule, or operation drift.

## Corroboration rule

One deviation creates an observation. Escalate an assessment only when independent evidence supports it. Signals derived from the same source or feature are not independent.

For each deviation report:

- baseline expectation;
- observed value and magnitude;
- evidence IDs;
- independent corroboration;
- contradicting evidence;
- benign alternatives;
- sensitive resources or privileges;
- confidence and next test.

## Benign explanations to test

- corporate VPN, secure web gateway, mobile carrier NAT, residential ISP, or VDI;
- approved travel, remote work, time-zone change, daylight saving, or unusual shift;
- device replacement, reset, browser update, enrollment, or privacy feature;
- approved help-desk, PIM, application, migration, or maintenance activity;
- service deployment, failover, scaling, certificate rotation, or patching;
- shared workstation or kiosk;
- legitimate OAuth consent or new application rollout;
- delayed, duplicated, sampled, or missing telemetry.

Do not treat a help-desk ticket, managed device, successful MFA, or trusted location as automatic clearance. These are disconfirming inputs whose integrity must also be considered.

## Anti-patterns

- Comparing service principals to human work hours.
- Using one global threshold for every identity.
- Treating a provider anomaly score as a verdict.
- Hard-coding numeric weights without tenant calibration.
- Training on an unverified or compromised period.
- Ignoring drift after reorganizations, migrations, or policy changes.
- Suppressing a signal without preserving the rationale and expiry.
