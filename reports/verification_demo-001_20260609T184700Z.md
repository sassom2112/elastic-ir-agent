## Verification Summary
Verified: 15 | Refuted: 0 | Unverifiable: 0

## Claim-by-Claim Results
| Claim | Status | Evidence |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell (T1059.003) - `cmd.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:42:53.295Z | VERIFIED | `MSEDGEWIN10` timeline shows `cmd.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:42:53.295Z. |
| Command and Scripting Interpreter: PowerShell (T1059.001) - `powershell.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:43:03.303Z | VERIFIED | `MSEDGEWIN10` timeline shows `powershell.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:43:03.303Z. |
| Windows Management Instrumentation (T1047) / Service Creation (T1543.003) - `sc.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:44:08.185Z | VERIFIED | `MSEDGEWIN10` timeline shows `sc.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:44:08.185Z. |
| Create or Modify System Process: Windows Service (T1543.003) - `AtomicService.exe` created by `NT AUTHORITY\SYSTEM` on `MSEDGEWIN10` at 2019-07-19T14:44:08.307Z | VERIFIED | `MSEDGEWIN10` timeline shows `AtomicService.exe` created by `NT AUTHORITY\SYSTEM` at 2019-07-19T14:44:08.307Z. |
| Compiled Code (T1059.005) - `csc.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:45:55.105Z | VERIFIED | `MSEDGEWIN10` timeline shows `csc.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:45:55.105Z. |
| Component Object Model and Distributed COM (T1559.001) / Event Triggered Execution (T1546) - `RegAsm.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:45:55.699Z | VERIFIED | `MSEDGEWIN10` timeline shows `RegAsm.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:45:55.699Z. |
| Component Object Model and Distributed COM (T1559.001) / Event Triggered Execution (T1546) - `RegSvcs.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:46:19.484Z | VERIFIED | `MSEDGEWIN10` timeline shows `RegSvcs.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:46:19.484Z. |
| Inhibit System Recovery (T1490) - `vssadmin.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:47:40.706Z | VERIFIED | `MSEDGEWIN10` timeline shows `vssadmin.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:47:40.706Z. |
| Inhibit System Recovery (T1490) - `wbadmin.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:47:45.624Z | VERIFIED | `MSEDGEWIN10` timeline shows `wbadmin.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:47:45.624Z. |
| Boot or Logon Autostart Execution: BCD Boot Options (T1547.006) - `bcdedit.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:47:51.865Z | VERIFIED | `MSEDGEWIN10` timeline shows `bcdedit.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:47:51.865Z. |
| Ingress Tool Transfer (T1105) - `bitsadmin.exe` created by `MSEDGEWIN10\IEUser` on `MSEDGEWIN10` at 2019-07-19T14:48:04.131Z | VERIFIED | `MSEDGEWIN10` timeline shows `bitsadmin.exe` created by `MSEDGEWIN10\IEUser` at 2019-07-19T14:48:04.131Z. |
| OS Credential Dumping: LSASS Memory (T1003.001) - `samir.exe` (event code 10) on `LAPTOP-JU4M3I0E` at 2020-10-27T10:17:18.377Z | VERIFIED | Credential access events show `samir.exe` on `LAPTOP-JU4M3I0E` at 2020-10-27T10:17:18.377Z. |
| OS Credential Dumping (T1003) - Event code 4663 by `IEUser` on `MSEDGEWIN10` at 2021-08-07T23:33:00.610Z | VERIFIED | Credential access events show event code 4663 by `IEUser` on `MSEDGEWIN10` at 2021-08-07T23:33:00.610Z. |
| OS Credential Dumping: LSASS Memory (T1003.001) - `MalSeclogon.exe` accessing `lsass.exe` (event code 10) on `MSEDGEWIN10` at 2021-12-07T17:33:01.638Z | VERIFIED | Credential access events show `MalSeclogon.exe` on `MSEDGEWIN10` at 2021-12-07T17:33:01.638Z. |
| Lateral Movement (T1021) - `IEUser` accessed 2 hosts, `user01` accessed 2 hosts. | VERIFIED | Lateral movement detection shows `IEUser` accessed 2 hosts and `user01` accessed 2 hosts. |
