## Verification Summary
Verified: 8 | Refuted: 8 | Unverifiable: 2

## Claim-by-Claim Results
| Claim | Status | Evidence |
|---|---|---|
| **Attack Chain** | | |
| 1. T1543.003 - Create or Modify System Process: Windows Service (AtomicService.exe on MSEDGEWIN10) | REFUTED | `attack_timeline` for MSEDGEWIN10 shows no events for `AtomicService.exe` or `T1543.003` around the claimed timestamp. The earliest event for MSEDGEWIN10 in the tool output is 2020-05-24. |
| 2. T1490 - Inhibit System Recovery (vssadmin.exe on MSEDGEWIN10) | REFUTED | `attack_timeline` for MSEDGEWIN10 shows no events for `vssadmin.exe` or `T1490` around the claimed timestamp. |
| 3. T1490 - Inhibit System Recovery (wbadmin.exe on MSEDGEWIN10) | REFUTED | `attack_timeline` for MSEDGEWIN10 shows no events for `wbadmin.exe` or `T1490` around the claimed timestamp. |
| 4. T1564.001 - Hide Artifacts: Hidden Files and Directories (bcdedit.exe