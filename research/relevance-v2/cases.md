# Published 120-query comparison

120 queries over the same 649 real events. Label revision 2.

This is a diagnostic challenge set, not production recall. Main queries use no device/time/event-type filters. Model-specific chunking and normalization are part of the evaluated retrieval setup. See [methodology](../../EVALUATION.md) and [provenance](../README.md).

The machine-readable [results](results.json) include all returned top-ten source row references and relevant/confuser labels, but deliberately omit raw telemetry and snippets. Reproduce locally to inspect the original evidence.

## Main results

| Retriever | Queries | Hit@1 | Hit@5 | Hit@10 | MRR@10 |
|---|---:|---:|---:|---:|---:|
| bm25 | 96 | 0.3958 | 0.5938 | 0.6979 | 0.4784 |
| minilm | 96 | 0.4688 | 0.7917 | 0.8542 | 0.5927 |
| securebert | 96 | 0.1250 | 0.2708 | 0.3333 | 0.1859 |

Hit@k means at least one field-relevant result in the first k. MRR@10 is the mean reciprocal first-relevant rank, counting ranks beyond ten as zero. The main average excludes mixed-evidence, absent-behavior, scope and short-query diagnostics.

## Every exact query

Ranks below are the first relevant result among the eligible events; lower is better. A dash means no relevant result exists in the candidate set. No-answer queries still return neighbors when candidates exist; there is no calibrated abstention.

| Case | Track | Exact query | Positives | BM25 rank | MiniLM rank | Cisco rank |
|---|---|---|---:|---:|---:|---:|
| scr-to-cmd-1 | main | Find cmd.exe launched by a parent executable ending in .scr. | 4 | 1 | 1 | 391 |
| scr-to-cmd-2 | main | Show a screensaver spawning the Windows command interpreter. | 4 | 16 | 13 | 188 |
| scr-to-cmd-3 | main | Look for shell execution originating from a screensaver rather than an ordinary terminal. | 4 | 39 | 32 | 308 |
| hidden-bypass-1 | main | Find PowerShell process creation using -ep bypass and -window hidden. | 2 | 2 | 5 | 24 |
| hidden-bypass-2 | main | Show hidden PowerShell launches that bypass execution policy. | 2 | 3 | 4 | 87 |
| hidden-bypass-3 | main | Which PowerShell executions suppress the window and bypass script execution restrictions? | 2 | 1 | 14 | 36 |
| image-payload-1 | main | Find PowerShell commands using System.Drawing.Bitmap, GetPixel and monkey.png. | 2 | 3 | 1 | 2 |
| image-payload-2 | main | Show PowerShell execution extracting code bytes from pixels in an image. | 2 | 60 | 1 | 3 |
| image-payload-3 | main | Look for image-based payload extraction in a PowerShell process command line. | 2 | 2 | 7 | 17 |
| powershell-compiler-1 | main | Find csc.exe process creation whose parent is powershell.exe. | 4 | 1 | 2 | 167 |
| powershell-compiler-2 | main | Show PowerShell spawning the C sharp compiler. | 4 | 19 | 52 | 20 |
| powershell-compiler-3 | main | Look for .NET compilation launched directly by a PowerShell process. | 4 | 1 | 18 | 17 |
| sdelete-zip-1 | main | Find sdelete64.exe commands targeting a .zip file. | 8 | 2 | 1 | 127 |
| sdelete-zip-2 | main | Show secure-delete utility launches against ZIP archives. | 8 | 8 | 3 | 252 |
| sdelete-zip-3 | main | Look for attempts to erase archive files with Sysinternals SDelete. | 8 | 4 | 76 | 198 |
| psexec-python-1 | main | Find PsExec64.exe commands targeting NASHUA and launching python.exe. | 8 | 1 | 1 | 1 |
| psexec-python-2 | main | Show PsExec attempts to start Python on the NASHUA host. | 8 | 8 | 2 | 56 |
| psexec-python-3 | main | Locate remote Python execution requests made with the Sysinternals execution tool. | 8 | 5 | 13 | 53 |
| rundll-webdav-1 | main | Find rundll32.exe executing davclnt.dll,DavSetCookie. | 8 | 1 | 1 | 31 |
| rundll-webdav-2 | main | Show Windows DLL runner launches invoking the WebDAV client cookie function. | 8 | 3 | 1 | 61 |
| rundll-webdav-3 | main | Look for WebDAV-related execution through rundll32, not ordinary shell32 activation. | 8 | 2 | 1 | 52 |
| javamtsup-execution-1 | main | Find process creation for C:\Windows\System32\javamtsup.exe. | 2 | 2 | 2 | 209 |
| javamtsup-execution-2 | main | Show the Java support service executable actually being started as a process. | 2 | 7 | 1 | 31 |
| javamtsup-execution-3 | main | Retrieve execution events for javamtsup, excluding its installation configuration. | 2 | 8 | 4 | 32 |
| powershell-child-1 | main | Find process creation where the new executable is powershell.exe, not just its parent. | 8 | 1 | 8 | 192 |
| powershell-child-2 | main | Show PowerShell starting, rather than programs started by PowerShell. | 8 | 23 | 2 | 128 |
| powershell-child-3 | main | Return launches of the shell itself; exclude conhost or csc children of PowerShell. | 8 | 14 | 7 | 8 |
| powershell-parent-1 | main | Find conhost.exe started by powershell.exe. | 8 | 1 | 1 | 131 |
| powershell-parent-2 | main | Show console-host child processes of PowerShell. | 8 | 34 | 1 | 20 |
| powershell-parent-3 | main | Retrieve the console helper launch caused by a PowerShell parent, not PowerShell's launch. | 8 | 6 | 1 | 24 |
| powershell-to-lsass-1 | main | Find process-access events where powershell.exe accesses lsass.exe. | 4 | 9 | 1 | 85 |
| powershell-to-lsass-2 | main | Show PowerShell opening a handle to the Windows authentication process. | 4 | 136 | 5 | 34 |
| powershell-to-lsass-3 | main | Investigate potential credential access: PowerShell is the accessor and LSASS the target. | 4 | 9 | 1 | 68 |
| lsass-to-powershell-1 | main | Find process-access events where lsass.exe accesses powershell.exe. | 8 | 1 | 5 | 12 |
| lsass-to-powershell-2 | main | Show the authentication process opening a handle to PowerShell, not the reverse. | 8 | 136 | 4 | 80 |
| lsass-to-powershell-3 | main | Retrieve accesses initiated by LSASS against PowerShell; exclude PowerShell accessing LSASS. | 8 | 2 | 5 | 77 |
| lsass-full-access-1 | main | Find PowerShell access to lsass.exe with GrantedAccess 0x1fffff. | 1 | 1 | 1 | 19 |
| lsass-full-access-2 | main | Show PowerShell obtaining full process access to LSASS rather than query-only access. | 1 | 12 | 3 | 16 |
| lsass-full-access-3 | main | Locate the LSASS handle opened by PowerShell with all-access rights. | 1 | 14 | 5 | 227 |
| lsass-remote-thread-1 | main | Find remote-thread creation from powershell.exe into lsass.exe. | 1 | 1 | 1 | 169 |
| lsass-remote-thread-2 | main | Show PowerShell starting a thread inside the authentication process. | 1 | 1 | 2 | 2 |
| lsass-remote-thread-3 | main | Look for LSASS thread-injection telemetry with PowerShell as the source. | 1 | 1 | 1 | 14 |
| lsass-query-only-1 | main | Find PowerShell access to LSASS with GrantedAccess 0x1000. | 2 | 5 | 1 | 24 |
| lsass-query-only-2 | main | Show query-limited-information handles from PowerShell to LSASS, not full-access handles. | 2 | 20 | 3 | 71 |
| lsass-query-only-3 | main | Separate PowerShell inspecting LSASS metadata from requests for all process rights. | 2 | 14 | 3 | 17 |
| powershell-443-1 | main | Find powershell.exe network connections with destination port 443. | 9 | 1 | 1 | 35 |
| powershell-443-2 | main | Show PowerShell connecting to the conventional HTTPS port. | 9 | 28 | 1 | 4 |
| powershell-443-3 | main | Which network events associate PowerShell with TCP destination port 443? | 9 | 1 | 1 | 25 |
| powershell-winrm-1 | main | Find powershell.exe connecting to 10.0.1.6 on destination port 5985. | 4 | 1 | 1 | 30 |
| powershell-winrm-2 | main | Show PowerShell connections to the WinRM HTTP listener at 10.0.1.6. | 4 | 1 | 3 | 9 |
| powershell-winrm-3 | main | Look for remote-management connection attempts from PowerShell to NASHUA's 5985 port. | 4 | 2 | 1 | 137 |
| powershell-ldap-1 | main | Find powershell.exe connecting to 10.0.0.4 on port 389. | 2 | 1 | 1 | 17 |
| powershell-ldap-2 | main | Show PowerShell contacting the LDAP listener on the domain controller. | 2 | 235 | 90 | 77 |
| powershell-ldap-3 | main | Look for directory-service connections from PowerShell to destination port 389. | 2 | 1 | 8 | 32 |
| gallery-dns-1 | main | Find powershell.exe DNS queries for www.powershellgallery.com. | 1 | 1 | 1 | 1 |
| gallery-dns-2 | main | Show PowerShell resolving the PowerShell Gallery domain. | 1 | 245 | 2 | 30 |
| gallery-dns-3 | main | Retrieve name-resolution evidence for the PowerShell package gallery, not TCP traffic. | 1 | 303 | 1 | 1 |
| psexec-rpc-1 | main | Find PsExec64.exe connecting to 10.0.1.6 on TCP port 135. | 5 | 1 | 1 | 18 |
| psexec-rpc-2 | main | Show PsExec contacting NASHUA's RPC endpoint mapper. | 5 | 584 | 5 | 20 |
| psexec-rpc-3 | main | Locate RPC connection evidence for PsExec remote execution, excluding DNS lookups. | 5 | 64 | 1 | 3 |
| folder-command-1 | main | Find Folder\shell\open\command\(Default) registry writes containing powershell. | 1 | 4 | 7 | 83 |
| folder-command-2 | main | Show a registry change replacing the folder-open command with PowerShell. | 1 | 4 | 3 | 71 |
| folder-command-3 | main | Look for folder-handler hijacking configuration that redirects execution to PowerShell. | 1 | 9 | 34 | 132 |
| delegate-empty-1 | main | Find an empty DelegateExecute value written under Folder\shell\open\command. | 1 | 1 | 1 | 5 |
| delegate-empty-2 | main | Show the folder shell handler's DelegateExecute value being set to empty. | 1 | 1 | 1 | 65 |
| delegate-empty-3 | main | Locate the empty delegation value accompanying a folder-open handler change. | 1 | 1 | 1 | 48 |
| service-imagepath-1 | main | Find a registry ImagePath write for the javamtsup service. | 1 | 1 | 1 | 1 |
| service-imagepath-2 | main | Show the executable path being configured for the Java support service. | 1 | 463 | 2 | 7 |
| service-imagepath-3 | main | Locate javamtsup's binary-path registry setting, not its start mode or display name. | 1 | 6 | 4 | 1 |
| defender-run-1 | main | Find WindowsDefender registry writes under CurrentVersion\Run. | 1 | 1 | 1 | 1 |
| defender-run-2 | main | Show Windows Defender configuring its logon autostart Run value. | 1 | 1 | 1 | 15 |
| defender-run-3 | main | Locate the Defender startup-entry change without labeling every Run-key write malicious. | 1 | 1 | 2 | 9 |
| draft-created-1 | main | Find file creation of Draft.Zip by powershell.exe. | 1 | 1 | 1 | 1 |
| draft-created-2 | main | Show PowerShell writing the Draft ZIP archive to disk. | 1 | 1 | 1 | 39 |
| draft-created-3 | main | Retrieve archive-creation evidence for Draft.Zip, not subsequent deletion activity. | 1 | 1 | 1 | 1 |
| monkey-created-1 | main | Find file-created events for monkey.png in a Downloads directory. | 1 | 1 | 1 | 3 |
| monkey-created-2 | main | Show the image payload file being written to the user's Downloads folder. | 1 | 4 | 1 | 1 |
| monkey-created-3 | main | Retrieve the creation of monkey.png rather than later PowerShell commands reading it. | 1 | 1 | 3 | 13 |
| policy-test-file-1 | main | Find PowerShell file creation for __PSScriptPolicyTest files ending in .ps1. | 8 | 1 | 1 | 6 |
| policy-test-file-2 | main | Show temporary PowerShell script-policy probe files. | 8 | 100 | 1 | 3 |
| policy-test-file-3 | main | Separate the shell's execution-policy test scripts from arbitrary dropped payload files. | 8 | 387 | 101 | 13 |
| powershell-dll-file-1 | main | Find powershell.exe creating .dll files under AppData\Local\Temp. | 8 | 1 | 1 | 2 |
| powershell-dll-file-2 | main | Show PowerShell writing a dynamic library into the user's temporary directory. | 8 | 228 | 20 | 1 |
| powershell-dll-file-3 | main | Look for a DLL dropped by PowerShell, excluding records that merely load a DLL. | 8 | 44 | 2 | 8 |
| psexesvc-installed-1 | main | Find service-installation events for PSEXESVC. | 8 | 4 | 1 | 1 |
| psexesvc-installed-2 | main | Show the PsExec helper being registered as a Windows service. | 8 | 4 | 1 | 2 |
| psexesvc-installed-3 | main | Retrieve evidence that the remote execution service was installed, not just started. | 8 | 5 | 27 | 1 |
| javamtsup-installed-1 | main | Find installation of the javamtsup Windows service. | 1 | 1 | 1 | 113 |
| javamtsup-installed-2 | main | Show the Java support executable being registered with the service manager. | 1 | 66 | 3 | 14 |
| javamtsup-installed-3 | main | Locate creation of the Java(TM) Virtual Machine Support Service, not its execution. | 1 | 98 | 4 | 4 |
| psexesvc-credentials-1 | main | Find explicit-credentials logons by PSEXESVC.exe using the pbeesly account. | 4 | 1 | 13 | 2 |
| psexesvc-credentials-2 | main | Show PsExec's service supplying explicit credentials for pbeesly. | 4 | 1 | 24 | 420 |
| psexesvc-credentials-3 | main | Retrieve credential-use audit events from the remote execution service, not logon success. | 4 | 132 | 10 | 216 |
| pbeesly-network-logon-1 | main | Find successful logons for pbeesly with LogonType 3. | 12 | 7 | 2 | 3 |
| pbeesly-network-logon-2 | main | Show successful network logons by pbeesly rather than interactive desktop logons. | 12 | 13 | 2 | 5 |
| pbeesly-network-logon-3 | main | Locate pbeesly's authenticated network sessions, excluding explicit-credential attempts. | 12 | 11 | 2 | 45 |
| psexec-mixed-evidence-1 | mixed | Find both PsExec64.exe process launches and installation events for PSEXESVC. | 16 | 4 | 2 | 10 |
| psexec-mixed-evidence-2 | mixed | Show PsExec execution evidence together with registration of its helper service. | 16 | 48 | 1 | 1 |
| psexec-mixed-evidence-3 | mixed | Collect the launch and service-install artifacts of PsExec, without asserting causality. | 16 | 45 | 3 | 1 |
| lsass-mixed-evidence-1 | mixed | Find PowerShell-to-LSASS process-access and remote-thread-creation events. | 5 | 1 | 1 | 20 |
| lsass-mixed-evidence-2 | mixed | Show both LSASS handle opening and thread injection involving PowerShell. | 5 | 1 | 1 | 9 |
| lsass-mixed-evidence-3 | mixed | Collect handle-access and remote-thread evidence with PowerShell as source and LSASS target. | 5 | 1 | 1 | 97 |
| absent-certutil | no-answer | Find certutil.exe downloading a file with -urlcache. | 0 | - | - | - |
| absent-shadow-delete | no-answer | Find vssadmin.exe deleting volume shadow copies. | 0 | - | - | - |
| absent-mshta | no-answer | Find mshta.exe executing a remote HTTP application. | 0 | - | - | - |
| absent-failed-logon | no-answer | Find failed authentication attempts for the pbeesly account. | 0 | - | - | - |
| absent-ip | no-answer | Find network connections whose destination is exactly 203.0.113.77. | 0 | - | - | - |
| absent-service | no-answer | Find installation of the BlueRagTestService Windows service. | 0 | - | - | - |
| pbeesly-network-logon-text-only | scope | Find successful network logons by pbeesly on NASHUA.dmevals.local. | 8 | 12 | 10 | 28 |
| pbeesly-network-logon-filtered | scope | Find successful network logons by pbeesly on NASHUA.dmevals.local. | 8 | 8 | 8 | 10 |
| powershell-443-text-only | scope | Find PowerShell connections to destination port 443 before 03:00 UTC on May 2, 2020. | 2 | 4 | 8 | 45 |
| powershell-443-filtered | scope | Find PowerShell connections to destination port 443 before 03:00 UTC on May 2, 2020. | 2 | 1 | 1 | 3 |
| empty-device | empty-scope | Find PowerShell connections to port 443. | 0 | - | - | - |
| empty-time | empty-scope | Find PowerShell connections to port 443. | 0 | - | - | - |
| powershell-to-lsass-short | robustness | powershel accessing lsass | 4 | 33 | 1 | 370 |
| lsass-remote-thread-short | robustness | Powershell creates remote thread in LSASS | 1 | 1 | 1 | 1 |
| psexesvc-installed-short | robustness | psexec service instalation | 8 | 1 | 1 | 30 |
| powershell-winrm-short | robustness | PowerShell to WinRM on 10.0.1.6 | 4 | 1 | 58 | 299 |
| rundll-webdav-short | robustness | rundll32 WebDAV DavSetCookie | 8 | 1 | 1 | 62 |
| folder-command-short | robustness | folder shell open command hijack powershell | 1 | 4 | 9 | 139 |
