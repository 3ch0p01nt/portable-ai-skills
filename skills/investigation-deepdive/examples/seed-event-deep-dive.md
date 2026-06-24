# Example: Seed Event Deep Dive

This example is synthetic and offline. It contains no customer data.

## Seed

At `2026-06-18T14:22:11Z`, `powershell.exe` launched from `winword.exe` on `HOST-042` under `user@example.com` with an encoded command and a network connection to `suspicious.example`.

## Investigation Plan

### Seed summary

Endpoint process execution from an Office parent process to PowerShell with encoded content and external network activity.

### Extracted entities

- Host: `HOST-042`
- User: `user@example.com`
- Parent process: `winword.exe`
- Child process: `powershell.exe`
- Command-line feature: encoded command
- Domain: `suspicious.example`
- Seed timestamp: `2026-06-18T14:22:11Z`

### Assumptions and missing context

- Defender or Sentinel endpoint telemetry is available.
- Live execution is not authorized in this example.
- Email, DNS, proxy, and identity telemetry may or may not be available.

### Time windows

- Endpoint pivots: T-24h to T+24h.
- Identity and email pivots: T-7d to T+48h.
- Prevalence baseline: T-30d.

### Initial hypotheses

1. Phishing-driven script execution.
2. Authorized macro-based business automation.
3. EDR false positive or benign encoded PowerShell.
4. Malware execution with command and control.

### Pivot plan

- Process tree around the seed time.
- Other encoded PowerShell on the same host.
- Domain and IP prevalence across hosts.
- Email delivery and click history for the user.
- User sign-ins before and after execution.
- File writes and child processes after PowerShell.

### Evidence to collect

- Process creation rows for `winword.exe` and `powershell.exe`.
- Network rows for `suspicious.example`.
- Email rows with matching sender, URL, attachment, or recipient.
- Sign-in rows for unusual geography, device, or MFA changes.
- File and registry rows after execution.
