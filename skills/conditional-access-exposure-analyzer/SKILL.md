---
name: "conditional-access-exposure-analyzer"
description: "Use whenever Rob asks to assess Microsoft Entra Conditional Access coverage, explain why Conditional Access did or did not apply to a workforce or workload sign-in, identify exclusions or weak controls, reconstruct historical effective policy, evaluate suspected policy weakening, or build identity/app/resource/client/flow coverage matrices. Perform authorized read-only analysis only; never create, update, delete, enable, disable, or otherwise modify Conditional Access."
---

# Conditional Access Exposure Analyzer

Perform authorized, read-only Microsoft Entra Conditional Access analysis. Never modify policies, named locations, authentication strengths, or related tenant objects. Treat all CA weaknesses as exposure—not compromise evidence.

## Method

1. Define tenant, UTC window, identities, applications, resources, client types, authentication flows, and available telemetry. Inventory retention, licensing, diagnostic coverage, snapshot availability, ingestion gaps, and exact feature/API status at the event and analysis dates. Missing evidence is unknown, never benign.

2. Preserve exact IDs and evidence references: sign-in/event ID, timestamp, user/service-principal/managed-identity object ID, appId, servicePrincipalId, agent blueprint/principal/instance/user IDs when exposed, resource ID, policy ID, group ID, role/template ID, named-location ID, authentication-strength ID, audit ID, snapshot time/hash, ticket, and pipeline run/commit.

3. Evaluate each exact tuple:
   `event time × token subject/object ID × identity class and parent lineage × home/resource tenant × direct/nested group and role membership × app/client ID × resource/action/authentication context × client app/protocol/platform × interactive/non-interactive/workload/agent flow × device state × IP/location × user/sign-in/agent risk × cross-tenant trust × session/CAE state`.

Keep these identity classes distinct when locally exposed:
- agent identity blueprint: template/manager object;
- blueprint principal: tenant-local principal for the blueprint;
- agent identity: running child instance;
- agent user: user-subject account paired to an agent identity.
Blueprint targeting can cover current and future child agent identities but not the paired agent users. User-delegated/OBO activity is evaluated against the user subject; autonomous activity is evaluated against the agent identity; agent-user activity is evaluated against that user subtype. Never assume “All users,” an agent-identity policy, or a blueprint target covers a different class. Record Preview/GA, API, licensing and enforcement state rather than importing current semantics into historical events.

4. Reconstruct identity scope at event time. Resolve direct and transitive group membership, role-assignable groups, directory-role inclusion, dynamic-group evidence, and explicit user/group/role exclusions. Verify role-based assignments use built-in directory roles: custom roles and administrative-unit/object-scoped roles aren't enforced as CA role assignments. Within one policy, a matching exclusion overrides inclusion. Policies are evaluated at token issuance, so membership changes do not retroactively affect an existing token. Do not use today’s membership as historical proof.

For external identities, distinguish B2B collaboration, B2B direct connect, service-provider/GDAP users, cross-tenant synchronization, and ordinary guests. B2B direct connect cannot fall back to resource-tenant MFA when the resource policy requires MFA: verify partner-specific inbound MFA trust or record the blocked/unknown outcome. Tenant Restrictions are a separate control plane from inbound/outbound cross-tenant settings; one does not prove the other. Partner-human attribution requires partner-side evidence.

5. Reconstruct policy and referenced-object state effective at event time from versioned snapshots and audit evidence. Distinguish enabled, report-only, disabled, deleted, Microsoft-managed, and unavailable historical state. Current Graph state describes only current posture. Snapshot not only the CA policy but referenced named locations, custom authentication strengths, authentication contexts, cross-tenant trust, and workload/agent objects; a referenced strength or trust change can alter effect without a CA policy diff.

6. For every policy, evaluate independently:
   - workforce, workload, external, agent identity, blueprint and agent-user inclusion/exclusion where available;
   - target application, resource, user action, or authentication context, including whether the context is published to apps;
   - client app, protocol, platform, device-filter polarity, location, risk, cross-tenant trust, and service-dependency conditions;
   - grant controls, operator semantics, authentication strength, external-authentication-method compatibility, and terms;
   - session controls, including sign-in frequency, persistent session, CAE, strict location, and token protection;
   - policy state and whether enforcement was possible for that subject and flow.

Treat device platform/OS derived from a client-controlled User-Agent as untrusted unless corroborated by device registration/compliance evidence. For unregistered devices, directory device properties are null: positive-match device filters do not match them. For external identities, reconstruct default and per-organization inbound trust for MFA/compliant/hybrid claims. Determine whether the tenant used the legacy or post-June-2026 baseline-scope enforcement model for “All resources” policies with exclusions; if historical state is unavailable, emit U01-HISTORICAL-STATE. Treat sole Require approved client app grants after the documented March-2026 retirement as non-enforcing; verify current product status rather than extrapolating.

7. Combine applicable enabled policies using effective CA semantics. Requirements from separate applicable policies accumulate; an applicable block dominates. Do not assume one “stronger” policy overrides another. Report-only results are observations, not enforcement. Disabled policies contribute no control. Treat Microsoft-managed, Baseline Security Mode, policy-as-code, and CA Optimization Agent activity as distinct change classes. A familiar service principal or report-only creation is not self-validating: require authoritative run/suggestion ID, intended diff, human approval, actor, source, and validity interval before treating it as expected. Identify interaction gaps only when combined semantics demonstrably leave an unintended path.

8. Validate authentication strength against the methods or claims actually used. Distinguish fresh authentication from previously satisfied MFA/device claims, token or session reuse, and non-interactive flows. During Backup Authentication Service operation, authentication-strength methods aren't re-evaluated when resilience defaults apply; identify the documented backup-auth issuer and historical session-control setting before calling this a gap. Do not call a successful or notApplied sign-in an MFA bypass without proving an unmet applicable requirement was evaded.

9. Evaluate workforce, workload, external and agent classes separately. For service principals, test direct workload-policy scope, resource, source network, risk where supported, identity type, and whether only block controls were supported at event time. A service principal placed in a group assigned to workload CA isn't enforced through that group. Managed identities and unsupported multitenant/first-party workloads must be labeled outside or unknown. For workload CAE, verify the exact supported service-principal/resource/capability combination; do not extend Microsoft Graph-only or single-tenant semantics to other resources.

For agents, verify the token subject, blueprint-to-instance lineage, supported conditions/grants, and whether the action used Entra authentication. Agent identities may support block-only enforcement while agent users can have different endpoint controls; verify locally. Blueprint token exchange/bootstrap operations and resources accessed through API keys can be outside CA; record them as explicit boundaries, not policy-failure findings. In OBO flows, consume user-policy and user-risk results and do not attribute them automatically to agent risk.

10. Compare reconstructed results with sign-in CA telemetry. Preserve top-level and per-policy results. notApplied alone proves only the represented event result; success may mean controls were satisfied. Payload omission, truncation, enum evolution, or serialization uncertainty must produce unknown, not a gap.

11. Use What If/Policy Impact only as supporting evidence. Record API/tool version and every supplied parameter. Under-specified context, target-app group mismatch, and omitted service dependencies can produce a non-match that is not a production counterfactual. Validate decisive claims against the historical policy graph and actual sign-in/per-policy result; never let a simulation override retained event evidence.

## Required matrices

### Event-policy matrix
One row per event-policy pair with event/time, exact subject class/ID and parent lineage, membership path, app/resource/client/flow, device/location/risk/session facts, policy ID/version/state, identity match, resource match, condition results, grants/sessions, reported per-policy result, reconstructed result, discrepancy, gap codes, confidence, and evidence IDs.

### Coverage matrix
One row per priority `identity class × resource × client/flow` scenario with expected controls, effective enabled controls, report-only controls, exclusions, uncovered path, gap codes, historical/current basis, owner/exception, coverage, confidence, and next read-only test.

### Change-benefit matrix
For suspected changes, record changed object/path, old/new values, actor user/app/SP/automation identity, authorization at the time, audit ID, snapshot hashes, ticket/pipeline/suggestion context, approval validity interval, change/use/revert times, benefited events, counterfactual result, and validation state.

## Deterministic gap codes

Emit every proven code; use the lowest numbered code as primary. Emit C00-COVERED only when no gap or unknown code applies.

- G01-EXCLUDED: matching identity, role, group, app/resource, platform, location, or client exclusion.
- G02-OUT-OF-SCOPE: required identity, app, resource, action, or authentication context was not included.
- G03-NON-ENFORCING: relevant policy was disabled, deleted, report-only, retired, or otherwise non-enforcing.
- G04-CLIENT-FLOW: legacy, non-interactive, protocol, platform, or flow path escaped intended enforcement.
- G05-AUTH-STRENGTH: absent or demonstrably weaker-than-required authentication grant/strength.
- G06-DEVICE: missing or ineffective compliance, join, approved-app, or supported token/device control.
- G07-LOCATION: stale, broad, incorrectly trusted, or uncovered location/network condition.
- G08-RISK: intended user/sign-in/service-principal/agent-risk condition was absent or ineffective.
- G09-SESSION: sign-in-frequency, persistent-session, resilience-default, CAE, revocation, strict-location, or supported token-protection gap. CAE-capable sessions can use long-lived tokens, supported critical events are reevaluated near real time, and policy/group propagation, unsupported clients/resources, and network outages can leave longer windows. Standard CAE location enforcement can issue a one-hour split-tunnel exception; strict enforcement is Preview and removes that exception. Never claim universal immediate revocation.
- G10-WORKLOAD: sensitive workload or agent identity lacked applicable directly assigned/supported CA.
- G11-NEW-OBJECT: newly introduced identity, app, resource, workload, blueprint/instance, or agent user had not entered intended scope.
- G12-POLICY-INTERACTION: combined enabled-policy semantics leave a proven unintended path.
- G13-EMERGENCY-EXCEPTION: emergency-account exclusion or use requiring invocation validation.
- U01-HISTORICAL-STATE: policy, membership, referenced object, named-location, strength, trust, license, or feature state at event time is unavailable.
- U02-TELEMETRY: decisive event context or per-policy evidence is absent, truncated, or unreliable.

## Counterfactual reasoning

For each alleged gap or weakening:
1. Evaluate the observed event under the best-supported historical state.
2. Evaluate the same fixed event context under the expected or pre-change state.
3. Label:
   - ENABLED-ACCESS only if old/expected state would block or impose a demonstrably unmet requirement while observed/new state allowed access.
   - NO-MATERIAL-EFFECT if both states yield the same outcome.
   - POSSIBLE-EFFECT if outcome depends on an unobserved claim or condition.
   - INDETERMINATE if historical state or decisive context is missing.
4. Never claim causation from timing alone.

## Coverage and confidence

Track: historical policy/referenced-object snapshot, identity hierarchy/lineage, exact sign-in context and CA results, workload/resource inventory, and audit/change/approval context.

- Complete: all decisive dimensions are time-aligned and evidenced.
- Partial: one non-decisive dimension is missing.
- Insufficient: any decisive dimension needed for the conclusion is missing.

Confidence cannot exceed coverage:
- High: exact IDs, time-valid state, complete matching path, and corroborating sign-in/audit evidence.
- Medium: supported but one non-decisive source is reconstructed or absent.
- Low: current-state substitution, incomplete membership/lineage, missing per-policy results, or material schema uncertainty.
- Unknown: no defensible effective-policy conclusion.

Separate confidence in CA exposure from confidence in malicious activity.

## False-positive tests

Test and document: approved enrollment/registration bootstrap; emergency invocation and custodians; expected non-interactive prior claims; exact time-valid ITSM record and intended diff; Terraform/policy-as-code/Optimization-Agent run, plan, approver, deployment identity, source and suggestion; Microsoft-managed or Baseline Security Mode lifecycle; migrations and baseline-scope rollout; vendor/service exceptions; B2B direct-connect and partner trust; service-provider/GDAP scope; named-location ownership/ranges; policy rollout/report-only stage; and documented rollback. Verify Azure DevOps is targeted directly—Windows Azure Service Management API coverage no longer implies Azure DevOps coverage. An allowlist, display name, ticket, or familiar automation actor alone is not validation.

## Risk model

Let B contain only non-CA evidence and valid sequence bonuses. Use:
- mCA=0.00: no relevant gap established
- mCA=0.05: unclear or low-impact gap
- mCA=0.10: verified missing control for exact identity/app/flow
- mCA=0.15: multiple relevant gaps or relevant report-only/disabled control
- mCA=0.25: both independently established—change unauthorized and counterfactual ENABLED-ACCESS; use at most 0.15 when either is unresolved or effect only possible

RiskScore = min(100, B × (1 + mCA)). If B=0, risk is zero. mCA never exceeds 0.25. Track engineering exposure separately. A verified unauthorized modification may contribute control-plane evidence to B; the multiplier represents facilitation and must not double-count it.

## Modification handoff

If an audit event, historical diff, or change/use/revert pattern suggests policy, named-location, authentication-strength, trust, or workload/agent-CA modification:
1. Continue read-only evidence preservation only.
2. Record actor user/app/SP, effective role/permission, audit IDs, changed paths, old/new snapshot hashes, source network, time-bounded approval/pipeline context, and benefited sign-ins.
3. Classify authorized, unauthorized, unresolved, or telemetry-insufficient.
4. Hand off evidence to identity incident response and CA/change-governance owner for independent validation and separately authorized containment.
5. Never perform or script rollback, disablement, exclusion removal, policy enablement, or any tenant mutation.

## Output

Provide an executive exposure summary, the three matrices, deterministic gap codes, counterfactual outcomes, coverage/confidence, false-positive results, bounded multiplier rationale, evidence IDs, unresolved questions, simulation limitations, and read-only handoffs. Keep observed facts, correlated facts, supported inferences, and coverage statements visibly separate.
