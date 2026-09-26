# Query results

120 queries, 649 real events, label revision 2.

Numbers are the first relevant result's rank; lower is better. A dash means no relevant event exists in the candidate set, not that search returned nothing. Matches is the number of relevant candidate events.

[Findings and method](../../EVALUATION.md) / [Full results](results.json)

## Behavior queries

| Query | Matches | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|---:|
| Find cmd.exe launched by a parent executable ending in .scr. | 4 | 1 | 1 | 391 |
| Show a screensaver spawning the Windows command interpreter. | 4 | 16 | 13 | 188 |
| Look for shell execution originating from a screensaver rather than an ordinary terminal. | 4 | 39 | 32 | 308 |
| Find PowerShell process creation using -ep bypass and -window hidden. | 2 | 2 | 5 | 24 |
| Show hidden PowerShell launches that bypass execution policy. | 2 | 3 | 4 | 87 |
| Which PowerShell executions suppress the window and bypass script execution restrictions? | 2 | 1 | 14 | 36 |
| Find PowerShell commands using System.Drawing.Bitmap, GetPixel and monkey.png. | 2 | 3 | 1 | 2 |
| Show PowerShell execution extracting code bytes from pixels in an image. | 2 | 60 | 1 | 3 |
| Look for image-based payload extraction in a PowerShell process command line. | 2 | 2 | 7 | 17 |
| Find csc.exe process creation whose parent is powershell.exe. | 4 | 1 | 2 | 167 |
| Show PowerShell spawning the C sharp compiler. | 4 | 19 | 52 | 20 |
| Look for .NET compilation launched directly by a PowerShell process. | 4 | 1 | 18 | 17 |
| Find sdelete64.exe commands targeting a .zip file. | 8 | 2 | 1 | 127 |
| Show secure-delete utility launches against ZIP archives. | 8 | 8 | 3 | 252 |
| Look for attempts to erase archive files with Sysinternals SDelete. | 8 | 4 | 76 | 198 |
| Find PsExec64.exe commands targeting NASHUA and launching python.exe. | 8 | 1 | 1 | 1 |
| Show PsExec attempts to start Python on the NASHUA host. | 8 | 8 | 2 | 56 |
| Locate remote Python execution requests made with the Sysinternals execution tool. | 8 | 5 | 13 | 53 |
| Find rundll32.exe executing davclnt.dll,DavSetCookie. | 8 | 1 | 1 | 31 |
| Show Windows DLL runner launches invoking the WebDAV client cookie function. | 8 | 3 | 1 | 61 |
| Look for WebDAV-related execution through rundll32, not ordinary shell32 activation. | 8 | 2 | 1 | 52 |
| Find process creation for C:\Windows\System32\javamtsup.exe. | 2 | 2 | 2 | 209 |
| Show the Java support service executable actually being started as a process. | 2 | 7 | 1 | 31 |
| Retrieve execution events for javamtsup, excluding its installation configuration. | 2 | 8 | 4 | 32 |
| Find process creation where the new executable is powershell.exe, not just its parent. | 8 | 1 | 8 | 192 |
| Show PowerShell starting, rather than programs started by PowerShell. | 8 | 23 | 2 | 128 |
| Return launches of the shell itself; exclude conhost or csc children of PowerShell. | 8 | 14 | 7 | 8 |
| Find conhost.exe started by powershell.exe. | 8 | 1 | 1 | 131 |
| Show console-host child processes of PowerShell. | 8 | 34 | 1 | 20 |
| Retrieve the console helper launch caused by a PowerShell parent, not PowerShell's launch. | 8 | 6 | 1 | 24 |
| Find process-access events where powershell.exe accesses lsass.exe. | 4 | 9 | 1 | 85 |
| Show PowerShell opening a handle to the Windows authentication process. | 4 | 136 | 5 | 34 |
| Investigate potential credential access: PowerShell is the accessor and LSASS the target. | 4 | 9 | 1 | 68 |
| Find process-access events where lsass.exe accesses powershell.exe. | 8 | 1 | 5 | 12 |
| Show the authentication process opening a handle to PowerShell, not the reverse. | 8 | 136 | 4 | 80 |
| Retrieve accesses initiated by LSASS against PowerShell; exclude PowerShell accessing LSASS. | 8 | 2 | 5 | 77 |
| Find PowerShell access to lsass.exe with GrantedAccess 0x1fffff. | 1 | 1 | 1 | 19 |
| Show PowerShell obtaining full process access to LSASS rather than query-only access. | 1 | 12 | 3 | 16 |
| Locate the LSASS handle opened by PowerShell with all-access rights. | 1 | 14 | 5 | 227 |
| Find remote-thread creation from powershell.exe into lsass.exe. | 1 | 1 | 1 | 169 |
| Show PowerShell starting a thread inside the authentication process. | 1 | 1 | 2 | 2 |
| Look for LSASS thread-injection telemetry with PowerShell as the source. | 1 | 1 | 1 | 14 |
| Find PowerShell access to LSASS with GrantedAccess 0x1000. | 2 | 5 | 1 | 24 |
| Show query-limited-information handles from PowerShell to LSASS, not full-access handles. | 2 | 20 | 3 | 71 |
| Separate PowerShell inspecting LSASS metadata from requests for all process rights. | 2 | 14 | 3 | 17 |
| Find powershell.exe network connections with destination port 443. | 9 | 1 | 1 | 35 |
| Show PowerShell connecting to the conventional HTTPS port. | 9 | 28 | 1 | 4 |
| Which network events associate PowerShell with TCP destination port 443? | 9 | 1 | 1 | 25 |
| Find powershell.exe connecting to 10.0.1.6 on destination port 5985. | 4 | 1 | 1 | 30 |
| Show PowerShell connections to the WinRM HTTP listener at 10.0.1.6. | 4 | 1 | 3 | 9 |
| Look for remote-management connection attempts from PowerShell to NASHUA's 5985 port. | 4 | 2 | 1 | 137 |
| Find powershell.exe connecting to 10.0.0.4 on port 389. | 2 | 1 | 1 | 17 |
| Show PowerShell contacting the LDAP listener on the domain controller. | 2 | 235 | 90 | 77 |
| Look for directory-service connections from PowerShell to destination port 389. | 2 | 1 | 8 | 32 |
| Find powershell.exe DNS queries for www.powershellgallery.com. | 1 | 1 | 1 | 1 |
| Show PowerShell resolving the PowerShell Gallery domain. | 1 | 245 | 2 | 30 |
| Retrieve name-resolution evidence for the PowerShell package gallery, not TCP traffic. | 1 | 303 | 1 | 1 |
| Find PsExec64.exe connecting to 10.0.1.6 on TCP port 135. | 5 | 1 | 1 | 18 |
| Show PsExec contacting NASHUA's RPC endpoint mapper. | 5 | 584 | 5 | 20 |
| Locate RPC connection evidence for PsExec remote execution, excluding DNS lookups. | 5 | 64 | 1 | 3 |
| Find Folder\shell\open\command\(Default) registry writes containing powershell. | 1 | 4 | 7 | 83 |
| Show a registry change replacing the folder-open command with PowerShell. | 1 | 4 | 3 | 71 |
| Look for folder-handler hijacking configuration that redirects execution to PowerShell. | 1 | 9 | 34 | 132 |
| Find an empty DelegateExecute value written under Folder\shell\open\command. | 1 | 1 | 1 | 5 |
| Show the folder shell handler's DelegateExecute value being set to empty. | 1 | 1 | 1 | 65 |
| Locate the empty delegation value accompanying a folder-open handler change. | 1 | 1 | 1 | 48 |
| Find a registry ImagePath write for the javamtsup service. | 1 | 1 | 1 | 1 |
| Show the executable path being configured for the Java support service. | 1 | 463 | 2 | 7 |
| Locate javamtsup's binary-path registry setting, not its start mode or display name. | 1 | 6 | 4 | 1 |
| Find WindowsDefender registry writes under CurrentVersion\Run. | 1 | 1 | 1 | 1 |
| Show Windows Defender configuring its logon autostart Run value. | 1 | 1 | 1 | 15 |
| Locate the Defender startup-entry change without labeling every Run-key write malicious. | 1 | 1 | 2 | 9 |
| Find file creation of Draft.Zip by powershell.exe. | 1 | 1 | 1 | 1 |
| Show PowerShell writing the Draft ZIP archive to disk. | 1 | 1 | 1 | 39 |
| Retrieve archive-creation evidence for Draft.Zip, not subsequent deletion activity. | 1 | 1 | 1 | 1 |
| Find file-created events for monkey.png in a Downloads directory. | 1 | 1 | 1 | 3 |
| Show the image payload file being written to the user's Downloads folder. | 1 | 4 | 1 | 1 |
| Retrieve the creation of monkey.png rather than later PowerShell commands reading it. | 1 | 1 | 3 | 13 |
| Find PowerShell file creation for __PSScriptPolicyTest files ending in .ps1. | 8 | 1 | 1 | 6 |
| Show temporary PowerShell script-policy probe files. | 8 | 100 | 1 | 3 |
| Separate the shell's execution-policy test scripts from arbitrary dropped payload files. | 8 | 387 | 101 | 13 |
| Find powershell.exe creating .dll files under AppData\Local\Temp. | 8 | 1 | 1 | 2 |
| Show PowerShell writing a dynamic library into the user's temporary directory. | 8 | 228 | 20 | 1 |
| Look for a DLL dropped by PowerShell, excluding records that merely load a DLL. | 8 | 44 | 2 | 8 |
| Find service-installation events for PSEXESVC. | 8 | 4 | 1 | 1 |
| Show the PsExec helper being registered as a Windows service. | 8 | 4 | 1 | 2 |
| Retrieve evidence that the remote execution service was installed, not just started. | 8 | 5 | 27 | 1 |
| Find installation of the javamtsup Windows service. | 1 | 1 | 1 | 113 |
| Show the Java support executable being registered with the service manager. | 1 | 66 | 3 | 14 |
| Locate creation of the Java(TM) Virtual Machine Support Service, not its execution. | 1 | 98 | 4 | 4 |
| Find explicit-credentials logons by PSEXESVC.exe using the pbeesly account. | 4 | 1 | 13 | 2 |
| Show PsExec's service supplying explicit credentials for pbeesly. | 4 | 1 | 24 | 420 |
| Retrieve credential-use audit events from the remote execution service, not logon success. | 4 | 132 | 10 | 216 |
| Find successful logons for pbeesly with LogonType 3. | 12 | 7 | 2 | 3 |
| Show successful network logons by pbeesly rather than interactive desktop logons. | 12 | 13 | 2 | 5 |
| Locate pbeesly's authenticated network sessions, excluding explicit-credential attempts. | 12 | 11 | 2 | 45 |

## Multiple event types

| Query | Matches | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|---:|
| Find both PsExec64.exe process launches and installation events for PSEXESVC. | 16 | 4 | 2 | 10 |
| Show PsExec execution evidence together with registration of its helper service. | 16 | 48 | 1 | 1 |
| Collect the launch and service-install artifacts of PsExec, without asserting causality. | 16 | 45 | 3 | 1 |
| Find PowerShell-to-LSASS process-access and remote-thread-creation events. | 5 | 1 | 1 | 20 |
| Show both LSASS handle opening and thread injection involving PowerShell. | 5 | 1 | 1 | 9 |
| Collect handle-access and remote-thread evidence with PowerShell as source and LSASS target. | 5 | 1 | 1 | 97 |

## Absent behaviors

| Query | Matches | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|---:|
| Find certutil.exe downloading a file with -urlcache. | 0 | - | - | - |
| Find vssadmin.exe deleting volume shadow copies. | 0 | - | - | - |
| Find mshta.exe executing a remote HTTP application. | 0 | - | - | - |
| Find failed authentication attempts for the pbeesly account. | 0 | - | - | - |
| Find network connections whose destination is exactly 203.0.113.77. | 0 | - | - | - |
| Find installation of the BlueRagTestService Windows service. | 0 | - | - | - |

## Host and time scope

| Query | Matches | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|---:|
| Find successful network logons by pbeesly on NASHUA.dmevals.local. (no filter) | 8 | 12 | 10 | 28 |
| Find successful network logons by pbeesly on NASHUA.dmevals.local. (filter: device=NASHUA.dmevals.local) | 8 | 8 | 8 | 10 |
| Find PowerShell connections to destination port 443 before 03:00 UTC on May 2, 2020. (no filter) | 2 | 4 | 8 | 45 |
| Find PowerShell connections to destination port 443 before 03:00 UTC on May 2, 2020. (filter: until=2020-05-02T03:00:00Z) | 2 | 1 | 1 | 3 |

## Empty scopes

| Query | Matches | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|---:|
| Find PowerShell connections to port 443. (filter: device=NO-SUCH-ENDPOINT) | 0 | - | - | - |
| Find PowerShell connections to port 443. (filter: since=2026-01-01T00:00:00Z) | 0 | - | - | - |

## Short queries and typos

| Query | Matches | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|---:|
| powershel accessing lsass | 4 | 33 | 1 | 370 |
| Powershell creates remote thread in LSASS | 1 | 1 | 1 | 1 |
| psexec service instalation | 8 | 1 | 1 | 30 |
| PowerShell to WinRM on 10.0.1.6 | 4 | 1 | 58 | 299 |
| rundll32 WebDAV DavSetCookie | 8 | 1 | 1 | 62 |
| folder shell open command hijack powershell | 1 | 4 | 9 | 139 |
