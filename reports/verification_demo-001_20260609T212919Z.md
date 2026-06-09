## Verification Summary
Verified: 0 | Refuted: 0 | Unverifiable: 0

## Claim-by-Claim Results
| Claim | Status | Evidence |
|---|---|---|
| Process created: C:\Windows\System32\cmd.exe on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\sc.exe (service creation/modification) on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\AtomicRedTeam\atomics\T1050\bin\AtomicService.exe on MSEDGEWIN10 by NT AUTHORITY\SYSTEM on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\reg.exe (registry modifications) on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\vssadmin.exe (shadow copy deletion attempt) on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\wbadmin.exe (backup catalog deletion attempt) on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\bcdedit.exe (boot configuration data modification) on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Process created: C:\Windows\System32\bitsadmin.exe (background intelligent transfer service) on MSEDGEWIN10 by MSEDGEWIN10\IEUser on 2019-07-19 | UNVERIFIABLE | The `attack_timeline` tool does not provide information about the user associated with process creation events. |
| Event code 10 (LSASS access) by samir.exe on LAPTOP-JU4M3I0E on 2020-10-27 | UNVERIFIABLE | The `credential_access_events` tool does not provide details about the specific process name (samir.exe) or the host (LAPTOP-JU4M3I0E) for LSASS access events. |
| 12x event 4663 (attempted access to an object) by IEUser on MSEDGEWIN10 on 2021-08-07 | UNVERIFIABLE | The `credential_access_events` tool does not provide details about specific event codes (4663), event counts (12x), or the user (IEUser) associated with object access events. |
| Event code 10 (LSASS access) by Z:\bouss\Downloads\MalSeclogon-master\x64\Debug\MalSeclogon.exe on MSEDGEWIN10 on 2021-12-07 | UNVERIFIABLE | The `credential_access_events` tool does not provide details about the specific process path (MalSeclogon.exe) or the host (MSEDGEWIN10) for LSASS access events. |
| MSEDGEWIN10, LAPTOP-JU4M3I0E are affected hosts | VERIFIED | Both MSEDGEWIN10 and LAPTOP-JU4M3I0E appear in the `attack_timeline` results, indicating activity on these hosts. |
| IEUser observed on 2 hosts (lateral movement) | UNVERIFIABLE | The `lateral_movement_detection` tool does not provide information about specific users involved in lateral movement or the number of hosts they moved between. |
| 9 hosts for '-' user lateral movement | UNVERIFIABLE | The `lateral_movement_detection` tool does not provide information about specific users (like '-') or the exact number of hosts involved in lateral movement. |
| NT AUTHORITY\SYSTEM, user01 are affected users | UNVERIFIABLE | The available tools do not provide a direct way to list all affected users or verify their involvement in specific activities. |
| Credential Access: T1003 — OS Credential Dumping | VERIFIED | The `unique_hosts_by_technique` tool identified "OS Credential Dumping" as a technique, indicating evidence of this activity. |
| Credential Access: T1003.001 — LSASS Memory | VERIFIED | The `unique_hosts_by_technique` tool identified "LSASS Memory" as a technique, indicating evidence of this activity. |
| Execution: T1059 — Command and Scripting Interpreter | VERIFIED | The `unique_hosts_by_technique` tool identified "Command and Scripting Interpreter" as a technique, indicating evidence of this activity. |
| Persistence: T1543.003 — Windows Service | VERIFIED | The `unique_hosts_by_technique` tool identified "Windows Service" as a technique, indicating evidence of this activity. |
| Persistence: T1547.001 — Registry Run Keys / Startup Folder | VERIFIED | The `unique_hosts_by_technique` tool identified "Registry Run Keys / Startup Folder" as a technique, indicating evidence of this activity. |
| Defense Evasion: T1490 — Inhibit System Recovery | VERIFIED | The `unique_hosts_by_technique` tool identified "Inhibit System Recovery" as a technique, indicating evidence of this activity. |
| Defense Evasion: T1564.001 — Hidden Files and Directories | VERIFIED | The `unique_hosts_by_technique` tool identified "Hidden Files and Directories" as a technique, indicating evidence of this activity. |
| Command and Control: T1197 — BITS Jobs | VERIFIED | The `unique_hosts_by_technique` tool identified "BITS Jobs" as a technique, indicating evidence of this activity. |
| Lateral Movement: T1078 — Valid Accounts | VERIFIED | The `unique_hosts_by_technique` tool identified "Valid Accounts" as a technique, indicating evidence of this activity. |
| Lateral movement detected | VERIFIED | The `lateral_movement_detection` tool returned results, indicating that lateral movement events were detected. |
| Failed logins detected | VERIFIED | The `failed_logins_by_host` tool returned results, indicating that failed login attempts were detected. |
| Suspicious process execution detected | VERIFIED | The `suspicious_process_execution` tool returned results, indicating that suspicious process execution events were detected. |
| Credential access events detected | VERIFIED | The `credential_access_events` tool returned results, indicating that credential access events were detected. |
