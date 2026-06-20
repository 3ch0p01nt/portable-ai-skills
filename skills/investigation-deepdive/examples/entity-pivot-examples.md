# Entity Pivot Examples

These examples are synthetic and offline.

## Domain Pivot Example

Seed: `credential-review.example`

Entity type: Domain.

Pivot plan:

1. Check endpoint prevalence for the domain.
2. Identify hosts, users, and processes that contacted it.
3. Check email URL delivery and click context.
4. Check DNS, proxy, firewall, or Sentinel logs if available.
5. Add missing source coverage to evidence gaps.

Benign alternatives:

- Marketing or click-tracking redirect.
- Security awareness simulation.
- Vendor update or SSO flow.
- Browser prefetch or proxy detonation.

## User Pivot Example

Seed: `alex@example.com`

Entity type: User.

Pivot plan:

1. Review failed and successful sign-ins.
2. Check new country, new device, MFA results, and conditional access.
3. Pivot to AuditLogs for role, group, authentication method, or app-consent changes.
4. Pivot to mailbox, cloud app, and endpoint activity tied to the user.
5. Separate suspicious authentication from proven post-compromise activity.

## Host Pivot Example

Seed: `HOST-042`

Entity type: Host.

Pivot plan:

1. Build process tree around the seed time.
2. Review file writes and hash prevalence.
3. Review network connections and DNS.
4. Review logons and remote sessions.
5. Review registry, scheduled task, service, and startup persistence.
6. Compare activity against peer hosts.
