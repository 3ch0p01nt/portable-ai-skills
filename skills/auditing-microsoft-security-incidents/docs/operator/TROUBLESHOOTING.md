# Troubleshooting

Use the pre-flight summary, `coverageGaps`, and adapter `errors` before rerunning. Most failures are intentional fail-closed controls.

| Symptom or code | Likely cause | Operator action |
| --- | --- | --- |
| `Az context is unavailable` | Az.Accounts is missing or no active sign-in exists. | Install Az.Accounts 5.x through the approved process, then sign in with the selected cloud environment and `<tenant-id>`. |
| `Az context environment must be ...` | Signed into the wrong Azure environment for `-Cloud`. | Reconnect with `AzureCloud` for Commercial or `AzureUSGovernment` for USGovDoD. |
| `Az context tenant does not match requested tenant` | Active Az tenant differs from `-TenantId`. | Reconnect using the intended `<tenant-id>`. |
| Subscription prompt blocks non-interactive DoD sign-in | `Connect-AzAccount` was run without `-Subscription` in a non-interactive shell. | Include the approved subscription during sign-in and use device authentication when required by the operator environment. |
| New sign-in appears ignored | A stale Az context with `Account.Type` of `AccessToken` is still active. | Check the active Az context. If the account type is not `User`, remove stale contexts, then reconnect. |
| Graph token acquisition failed for `SecurityIncident.Read.All` | The Microsoft Graph PowerShell public client lacks delegated consent or the client is unavailable. | Operator or admin decides whether to grant consent. Use `-AllowGraphUnavailable` only to record Graph as a gap. |
| Admin-consent warning appears before Graph sign-in | The pilot is reminding the operator that HAVOC never grants tenant consent. | Do not choose organization-wide consent in the sign-in prompt. If consent is not already approved, cancel or use `-AllowGraphUnavailable` when acceptable. |
| Graph token contains excess privilege scopes | Current Graph token has write-capable or unapproved scopes. | Use a least-privilege account/session and rerun. |
| Graph sign-in in DoD shows no consent prompt | Delegated `SecurityIncident.Read.All` is already granted for the Graph PowerShell public client. | Continue; the tool did not grant consent. |
| ARM or Log Analytics pre-flight token validation failed | The token cache, audience, issuer, tenant, or environment does not match the selected cloud profile. | Reconnect with the correct `-Cloud` environment and `<tenant-id>`. These checks are required even when Graph is unavailable. |
| Token audience, issuer, or tenant mismatch | Token does not match selected cloud profile or tenant. | Clear the session, reconnect to the correct environment and tenant, then rerun. |
| `trusted_transport_required` | Runner was called without the trusted transport. | Use the pilot wrapper script for live pilots or inject the approved transport in tests. |
| `safety_policy_denied` or policy reason such as `body_not_allowed_on_get` | Guard denied a request shape. | Treat as a safety stop. Check operation ID, method, query keys, body use, time range, and selected cloud. |
| `policy_invalid` or cloud profile pin mismatch | Policy or cloud profile no longer matches the pinned digest. | Pause and return the policy or profile files to the approved pinned version, or request an approved maintainer repin. |
| `guard_ipc_invalid` | Guard subprocess input envelope was malformed. | Rerun from a clean shell; if repeated, capture the command line without tenant data for maintainer review. |
| `adapter_invocation_failed` | An approved adapter failed before returning an envelope. | Review the adapter error, permissions, and input parameters; do not bypass the adapter. |
| `provenance_context_malformed` on every call | Old build with malformed live provenance context output. | Update to a build containing the 2026-09-29 fix and rerun. |
| `auth_scope_missing` on `log-analytics-query` | Old policy expected `Data.Read`, but DoD delegated Log Analytics tokens carry `user_impersonation`. | Update to a build where `log-analytics-query` requires `user_impersonation`; rerun pre-flight. |
| HTTP 404 from Graph `/security/incidents/{id}` | Sentinel-native incident is not onboarded to the Defender portal, so Graph has no Defender incident object. | Treat as expected for Sentinel-native cases. Use `IncidentNumber` as `-IncidentId`, pass the incident name GUID as `-SentinelIncidentId`, and rely on the Log Analytics fallback. |
| `securityincident_not_matched` | No Sentinel `SecurityIncident` row matched the provided incident identifiers. | Check incident ID, Sentinel incident ID, time window, workspace, and coverage. |
| `sentinel_source_not_covered` | Sentinel ARM source coverage was not attested, or the source scope was not covered by trusted provenance. | Rerun with `-AttestSentinelWorkspaceCoverage` only if the operator can attest onboarding and connector health; otherwise record the gap. |
| `sentinel_connector_unhealthy` | Read-only verification observed unhealthy connector or workspace state. | Fix Sentinel onboarding or connector health outside HAVOC; rerun after approval. |
| `sentinel_not_onboarded` | Read-only verification observed Sentinel not onboarded or disabled. | Onboard Sentinel outside HAVOC, or record the gap. |
| `sentinel_attestation_contradicted` | Operator attestation conflicted with read-only evidence. | Treat Sentinel coverage as not clean; investigate the contradiction. |
| `pivot_mutation_scanner_blocked` | A pivot looked write-capable or unsafe. | Do not run the pivot. Review the micro-skill pivot text and keep the gap. |
| `detection_quality_unavailable` | Detection-quality kernel could not assemble from current inputs. | Review missing rule metadata or coverage gaps. |
| `report_assembly_failed` | Report kernel failed on the available bundle. | Keep `bundle.json` private and provide sanitized failure details to maintainers. |
| Pester command not found or wrong version | Pester 5.7.1 is not installed in the PowerShell session. | Reinstall Pester 5.7.1 through the approved process, then rerun the targeted smoke test. |
| Shareable converter says input files are missing | Input directory lacks `report.md` or `report.json`. | Run the audit first or point to the correct output directory. |
| Shareable converter rejects output location | Output equals input or is under `InputDirectory\protected`. | Choose a separate local output folder. |
| Residual tenant identifiers remain | Post-scrub check found terms that would leak. | Add explicit `-AdditionalTerms` or remove sensitive input, then rerun. |

Do not work around guard, transport, token, or policy failures. A fail-closed result is safer than an unaudited tenant call.

## Coverage gap codes

| Gap | Meaning | Operator action |
| --- | --- | --- |
| `pivot_budget_truncated` | One or more validated pivots stayed on the frontier because `-MaxPivotQueries` was exhausted or could not cover all same-depth account variants. | Increase `-MaxPivotQueries` within the approved 1 to 100 range, narrow the pilot, or record the unexamined frontier as a limitation. |
| `pivot_result_capped` | A pivot returned exactly the runner row cap, so the result may be truncated. | Treat returned rows as evidence, but do not claim no additional matching activity exists. Narrow the query window or run an approved follow-up. |
| `containment_recovery_evidence_missing` | Containment and recovery validation evidence was absent. In live runs this is expected because live Graph incident responses do not supply the fixture-only containment/recovery review object. | Record the gap. Use separate approved evidence sources or manual review for containment and recovery validation. |
| `containment_recovery_validation_unavailable` | Some containment/recovery evidence was present, but validator records could not be projected from current read-only inputs. | Check whether the evidence has the expected fields and protected citations; otherwise keep the limitation. |
| `severity_history_not_supplied` | Severity change history was absent. | Do not infer severity never changed. Provide SecurityIncident history or accept the taxonomy limitation. |
| `classification_history_not_supplied` | Classification change history was absent. | Do not infer classification never changed. Provide history or accept the taxonomy limitation. |
| `status_history_not_supplied` | Status change history was absent. | Do not infer status never changed. Provide history or accept the taxonomy limitation. |
| `grouping_audit_not_supplied` | Alert-to-incident grouping, merge, split, and orphan checks were not assessed. | Supply grouping history from an approved source or record that grouping was not reviewed. |
| `grouping_depth_unknown` | Grouping depth was missing or non-numeric. | Provide a numeric depth or treat the grouping audit as depth-unknown. |
| `grouping_depth_*` | Grouping audit reached the shown depth but was bounded by data limits. | Treat grouping findings as bounded to that depth; expand approved data if deeper grouping matters. |
| `minimum_priority_frontier_unexamined` | Saturation is blocked because minimum-priority frontier items remain unexamined. | Examine or explicitly carry forward Tier-0 identity, critical-service, recovery-infrastructure, and reachable high-impact asset items before claiming saturation. |

## New report fields

| Field or section | Meaning | Operator action |
| --- | --- | --- |
| SOC handling score `not_assessable` | The composed score lacked at least two assessable decision snapshots or enough known weighted dimensions. | Do not treat this as a positive or negative handling score. Review missing inputs and decision-time evidence. |
| Known-weight normalization | SOC score averages only dimensions with known scores once enough weight is present. | Check the dimension breakdown before comparing scores across incidents. |
| Invalid hindsight critique | A critique used only post-decision evidence and is excluded from decision-time scoring. | Use it only as an outcome observation, not as proof of what an analyst should have known. |
| Taxonomy history audit | Severity, classification, and status changes are checked for flips, post-closure changes, unreviewed automation, and rationale gaps. | Investigate discrepancies, especially closure or automation changes without supporting rationale. |
| Frontier priority score and floor | Frontier items are ranked by weighted priority; Tier-0, critical-service, recovery-infrastructure, and reachable high-impact assets keep a minimum-priority floor. | Review minimum-priority items even when expected information gain appears low, or document the unexamined frontier. |
