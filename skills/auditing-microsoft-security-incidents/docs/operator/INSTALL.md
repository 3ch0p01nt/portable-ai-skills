# Install HAVOC Microsoft Incident Auditor

## Prerequisites

- PowerShell 7.4 or later.
- Az.Accounts 5.x for live pilots.
- Pester 5.7.1 only when running tests.
- No local administrator rights are required by the pack. Use normal user write access to the chosen working folder.

The live pilot is read-only, but Azure and Graph permissions are still tenant decisions. Do not place secrets, tenant identifiers, raw evidence, or tokens in this repository.

## Placement

Keep the pack in a local development folder such as:

```powershell
<local-pack-root>
```

Do not edit Copilot installed-plugin folders directly. Package and move the repository content through normal plugin metadata or the operator-approved distribution process.

## Verify the pack

Run validation from the repository root of the local pack. Use the structure validator script with `-PackRoot .`, run the Pester validation suite when Pester 5.7.1 is installed, and run the contract fixture validator with Python. Keep all outputs local and review failures before distribution.

If Pester is unavailable or the version is not 5.7.1, reinstall Pester 5.7.1 by the organization-approved PowerShell module process and rerun the targeted smoke test. Do not skip the contract validator.
