"""Field-labeled retrieval cases for the pinned OTRF APT29 day-one dataset."""

import re
from dataclasses import dataclass
from typing import Literal

from .events import Event, first_value


def evidence_type(event: Event) -> str:
    # Ground-truth provider equivalence; do not change the text sent to either encoder.
    if (
        event.metadata["channel"].casefold() == "system"
        and first_value(event.raw, "EventID", "EventId") == "7045"
    ):
        return "service_installed"
    return event.metadata["event_type"]


@dataclass(frozen=True)
class Field:
    names: tuple[str, ...]
    operation: Literal["equals", "contains", "endswith", "regex"]
    value: str

    def matches(self, event: Event) -> bool:
        value = (first_value(event.raw, *self.names) or "").casefold()
        expected = self.value.casefold()
        if self.operation == "equals":
            return value == expected
        if self.operation == "contains":
            return expected in value
        if self.operation == "endswith":
            return value.endswith(expected)
        return re.search(self.value, value, re.IGNORECASE) is not None


@dataclass(frozen=True)
class Rule:
    types: tuple[str, ...]
    fields: tuple[Field, ...] = ()

    def matches(self, event: Event) -> bool:
        return evidence_type(event) in self.types and all(
            field.matches(event) for field in self.fields
        )


@dataclass(frozen=True)
class Hunt:
    id: str
    category: str
    description: str
    queries: tuple[str, str, str]
    positive: tuple[Rule, ...]
    confusers: tuple[Rule, ...]
    required_types: tuple[str, ...] = ()
    absent: bool = False

    def relevant(self, event: Event) -> bool:
        return any(rule.matches(event) for rule in self.positive)

    def confusable(self, event: Event) -> bool:
        return not self.relevant(event) and any(rule.matches(event) for rule in self.confusers)


def field(
    names: str,
    operation: Literal["equals", "contains", "endswith", "regex"],
    value: str,
) -> Field:
    if operation not in {"equals", "contains", "endswith", "regex"}:
        raise ValueError(f"Unknown field operation: {operation}")
    return Field(tuple(names.split("|")), operation, value)


def rule(types: str, *fields: Field) -> Rule:
    return Rule(tuple(types.split("|")), fields)


PS = field("Image|NewProcessName", "endswith", r"\powershell.exe")
PARENT_PS = field("ParentImage|ParentProcessName", "endswith", r"\powershell.exe")
SOURCE_PS = field("SourceImage", "endswith", r"\powershell.exe")
TARGET_PS = field("TargetImage", "endswith", r"\powershell.exe")
SOURCE_LSASS = field("SourceImage", "endswith", r"\lsass.exe")
TARGET_LSASS = field("TargetImage", "endswith", r"\lsass.exe")
PSEXEC = field("Image|NewProcessName", "endswith", r"\psexec64.exe")
PROC = rule("process_creation")
NET = rule("network_connection")
ACCESS = rule("process_access")
REGISTRY = rule("registry_value_set")
FILES = rule("file_created|file_deleted")


HUNTS = (
    Hunt(
        "scr-to-cmd",
        "parent-child",
        "cmd.exe creation with a screensaver executable as its parent, not any cmd.exe event.",
        (
            "Find cmd.exe launched by a parent executable ending in .scr.",
            "Show a screensaver spawning the Windows command interpreter.",
            "Look for shell execution originating from a screensaver "
            "rather than an ordinary terminal.",
        ),
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\cmd.exe"),
                field("ParentImage|ParentProcessName", "endswith", ".scr"),
            ),
        ),
        (rule("process_creation", field("Image|NewProcessName", "endswith", r"\cmd.exe")),),
    ),
    Hunt(
        "hidden-bypass",
        "command-semantics",
        "The created process itself is PowerShell and its own command has bypass and hidden flags.",
        (
            "Find PowerShell process creation using -ep bypass and -window hidden.",
            "Show hidden PowerShell launches that bypass execution policy.",
            "Which PowerShell executions suppress the window "
            "and bypass script execution restrictions?",
        ),
        (
            rule(
                "process_creation",
                PS,
                field("CommandLine", "contains", "bypass"),
                field("CommandLine", "contains", "hidden"),
            ),
        ),
        (rule("process_creation", PARENT_PS), rule("process_creation", PS)),
    ),
    Hunt(
        "image-payload",
        "command-semantics",
        "PowerShell's own command reads monkey.png and invokes GetPixel; not a child quoting it.",
        (
            "Find PowerShell commands using System.Drawing.Bitmap, GetPixel and monkey.png.",
            "Show PowerShell execution extracting code bytes from pixels in an image.",
            "Look for image-based payload extraction in a PowerShell process command line.",
        ),
        (
            rule(
                "process_creation",
                PS,
                field("CommandLine", "contains", "monkey.png"),
                field("CommandLine", "contains", "GetPixel"),
            ),
        ),
        (rule("process_creation", field("ParentCommandLine", "contains", "GetPixel")), FILES),
    ),
    Hunt(
        "powershell-compiler",
        "parent-child",
        "csc.exe is the child and powershell.exe is the parent.",
        (
            "Find csc.exe process creation whose parent is powershell.exe.",
            "Show PowerShell spawning the C sharp compiler.",
            "Look for .NET compilation launched directly by a PowerShell process.",
        ),
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\csc.exe"),
                PARENT_PS,
            ),
        ),
        (
            rule("process_creation", PS),
            rule(
                "process_creation", field("ParentImage|ParentProcessName", "endswith", r"\csc.exe")
            ),
        ),
    ),
    Hunt(
        "sdelete-zip",
        "command-semantics",
        "SDelete process creation targets a .zip path; it is not proof the deletion succeeded.",
        (
            "Find sdelete64.exe commands targeting a .zip file.",
            "Show secure-delete utility launches against ZIP archives.",
            "Look for attempts to erase archive files with Sysinternals SDelete.",
        ),
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\sdelete64.exe"),
                field("CommandLine", "contains", ".zip"),
            ),
        ),
        (
            rule("process_creation", field("Image|NewProcessName", "endswith", r"\sdelete64.exe")),
            rule("file_created", field("TargetFilename", "endswith", ".zip")),
        ),
    ),
    Hunt(
        "psexec-python",
        "command-semantics",
        "PsExec process command names NASHUA and python.exe; does not prove remote success.",
        (
            "Find PsExec64.exe commands targeting NASHUA and launching python.exe.",
            "Show PsExec attempts to start Python on the NASHUA host.",
            "Locate remote Python execution requests made with the Sysinternals execution tool.",
        ),
        (
            rule(
                "process_creation",
                PSEXEC,
                field("CommandLine", "contains", "NASHUA"),
                field("CommandLine", "contains", "python.exe"),
            ),
        ),
        (
            rule("process_creation", field("Image|NewProcessName", "endswith", r"\python.exe")),
            rule("service_installed"),
        ),
    ),
    Hunt(
        "rundll-webdav",
        "command-semantics",
        "rundll32 own command invokes davclnt.dll,DavSetCookie; distinguish shell32 use.",
        (
            "Find rundll32.exe executing davclnt.dll,DavSetCookie.",
            "Show Windows DLL runner launches invoking the WebDAV client cookie function.",
            "Look for WebDAV-related execution through rundll32, not ordinary shell32 activation.",
        ),
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\rundll32.exe"),
                field("CommandLine", "contains", "DavSetCookie"),
            ),
        ),
        (rule("process_creation", field("Image|NewProcessName", "endswith", r"\rundll32.exe")),),
    ),
    Hunt(
        "javamtsup-execution",
        "event-type",
        "A javamtsup.exe process creation, not a service-install or registry event mentioning it.",
        (
            "Find process creation for C:\\Windows\\System32\\javamtsup.exe.",
            "Show the Java support service executable actually being started as a process.",
            "Retrieve execution events for javamtsup, excluding its installation configuration.",
        ),
        (rule("process_creation", field("Image|NewProcessName", "endswith", r"\javamtsup.exe")),),
        (
            rule("service_installed", field("ServiceName", "equals", "javamtsup")),
            rule("registry_value_set", field("TargetObject", "contains", "javamtsup")),
        ),
    ),
    Hunt(
        "powershell-child",
        "parent-child",
        "The new executable is PowerShell; a parent command mentioning PowerShell is insufficient.",
        (
            "Find process creation where the new executable is powershell.exe, "
            "not just its parent.",
            "Show PowerShell starting, rather than programs started by PowerShell.",
            "Return launches of the shell itself; exclude conhost or csc children of PowerShell.",
        ),
        (rule("process_creation", PS),),
        (rule("process_creation", PARENT_PS),),
    ),
    Hunt(
        "powershell-parent",
        "parent-child",
        "conhost.exe is the created executable and PowerShell is its parent.",
        (
            "Find conhost.exe started by powershell.exe.",
            "Show console-host child processes of PowerShell.",
            "Retrieve the console helper launch caused by a PowerShell parent, "
            "not PowerShell's launch.",
        ),
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\conhost.exe"),
                PARENT_PS,
            ),
        ),
        (
            rule("process_creation", PS),
            rule("process_creation", field("Image|NewProcessName", "endswith", r"\conhost.exe")),
        ),
    ),
    Hunt(
        "powershell-to-lsass",
        "direction",
        "Process-access SourceImage is PowerShell and TargetImage is LSASS; no dump claim.",
        (
            "Find process-access events where powershell.exe accesses lsass.exe.",
            "Show PowerShell opening a handle to the Windows authentication process.",
            "Investigate potential credential access: PowerShell is the accessor "
            "and LSASS the target.",
        ),
        (rule("process_access", SOURCE_PS, TARGET_LSASS),),
        (rule("process_access", SOURCE_LSASS, TARGET_PS), rule("remote_thread_created")),
    ),
    Hunt(
        "lsass-to-powershell",
        "direction",
        "Reverse control: LSASS is the accessor, PowerShell is the accessed process.",
        (
            "Find process-access events where lsass.exe accesses powershell.exe.",
            "Show the authentication process opening a handle to PowerShell, not the reverse.",
            "Retrieve accesses initiated by LSASS against PowerShell; "
            "exclude PowerShell accessing LSASS.",
        ),
        (rule("process_access", SOURCE_LSASS, TARGET_PS),),
        (rule("process_access", SOURCE_PS, TARGET_LSASS),),
    ),
    Hunt(
        "lsass-full-access",
        "exact-value",
        "PowerShell-to-LSASS process access specifically grants mask 0x1fffff.",
        (
            "Find PowerShell access to lsass.exe with GrantedAccess 0x1fffff.",
            "Show PowerShell obtaining full process access to LSASS rather than query-only access.",
            "Locate the LSASS handle opened by PowerShell with all-access rights.",
        ),
        (
            rule(
                "process_access",
                SOURCE_PS,
                TARGET_LSASS,
                field("GrantedAccess", "equals", "0x1fffff"),
            ),
        ),
        (rule("process_access", SOURCE_PS, TARGET_LSASS),),
    ),
    Hunt(
        "lsass-remote-thread",
        "event-type",
        "A remote-thread creation from PowerShell into LSASS, not merely a process handle.",
        (
            "Find remote-thread creation from powershell.exe into lsass.exe.",
            "Show PowerShell starting a thread inside the authentication process.",
            "Look for LSASS thread-injection telemetry with PowerShell as the source.",
        ),
        (rule("remote_thread_created", SOURCE_PS, TARGET_LSASS),),
        (
            rule("process_access", SOURCE_PS, TARGET_LSASS),
            rule("remote_thread_created", TARGET_LSASS),
        ),
    ),
    Hunt(
        "lsass-query-only",
        "exact-value",
        "PowerShell-to-LSASS access mask 0x1000, without treating it as a memory dump.",
        (
            "Find PowerShell access to LSASS with GrantedAccess 0x1000.",
            "Show query-limited-information handles from PowerShell to LSASS, "
            "not full-access handles.",
            "Separate PowerShell inspecting LSASS metadata from requests for all process rights.",
        ),
        (
            rule(
                "process_access",
                SOURCE_PS,
                TARGET_LSASS,
                field("GrantedAccess", "equals", "0x1000"),
            ),
        ),
        (rule("process_access", SOURCE_PS, TARGET_LSASS),),
    ),
    Hunt(
        "powershell-443",
        "network",
        "A PowerShell network event with destination port 443; port alone does not prove TLS.",
        (
            "Find powershell.exe network connections with destination port 443.",
            "Show PowerShell connecting to the conventional HTTPS port.",
            "Which network events associate PowerShell with TCP destination port 443?",
        ),
        (rule("network_connection", PS, field("DestinationPort", "equals", "443")),),
        (rule("network_connection", PS), rule("dns_query", PS)),
    ),
    Hunt(
        "powershell-winrm",
        "network",
        "PowerShell connects to 10.0.1.6:5985; this is connection evidence, not session success.",
        (
            "Find powershell.exe connecting to 10.0.1.6 on destination port 5985.",
            "Show PowerShell connections to the WinRM HTTP listener at 10.0.1.6.",
            "Look for remote-management connection attempts from PowerShell to NASHUA's 5985 port.",
        ),
        (
            rule(
                "network_connection",
                PS,
                field("DestinationIp", "equals", "10.0.1.6"),
                field("DestinationPort", "equals", "5985"),
            ),
        ),
        (
            rule("network_connection", PS),
            rule("network_connection", field("SourcePort", "equals", "5985")),
        ),
    ),
    Hunt(
        "powershell-ldap",
        "network",
        "PowerShell network events with destination 10.0.0.4:389.",
        (
            "Find powershell.exe connecting to 10.0.0.4 on port 389.",
            "Show PowerShell contacting the LDAP listener on the domain controller.",
            "Look for directory-service connections from PowerShell to destination port 389.",
        ),
        (
            rule(
                "network_connection",
                PS,
                field("DestinationIp", "equals", "10.0.0.4"),
                field("DestinationPort", "equals", "389"),
            ),
        ),
        (rule("network_connection", PS),),
    ),
    Hunt(
        "gallery-dns",
        "dns-versus-connection",
        "DNS query by PowerShell for www.powershellgallery.com, not a connection record.",
        (
            "Find powershell.exe DNS queries for www.powershellgallery.com.",
            "Show PowerShell resolving the PowerShell Gallery domain.",
            "Retrieve name-resolution evidence for the PowerShell package gallery, "
            "not TCP traffic.",
        ),
        (rule("dns_query", PS, field("QueryName", "equals", "www.powershellgallery.com")),),
        (rule("network_connection", PS), rule("dns_query", PS)),
    ),
    Hunt(
        "psexec-rpc",
        "network",
        "PsExec connects to 10.0.1.6:135, not merely resolving the machine's name.",
        (
            "Find PsExec64.exe connecting to 10.0.1.6 on TCP port 135.",
            "Show PsExec contacting NASHUA's RPC endpoint mapper.",
            "Locate RPC connection evidence for PsExec remote execution, excluding DNS lookups.",
        ),
        (
            rule(
                "network_connection",
                PSEXEC,
                field("DestinationIp", "equals", "10.0.1.6"),
                field("DestinationPort", "equals", "135"),
            ),
        ),
        (rule("dns_query", PSEXEC), rule("process_creation", PSEXEC), NET),
    ),
    Hunt(
        "folder-command",
        "registry",
        "Registry value-set changes the default Folder shell open command to PowerShell.",
        (
            "Find Folder\\shell\\open\\command\\(Default) registry writes containing powershell.",
            "Show a registry change replacing the folder-open command with PowerShell.",
            "Look for folder-handler hijacking configuration "
            "that redirects execution to PowerShell.",
        ),
        (
            rule(
                "registry_value_set",
                field("TargetObject", "endswith", r"\Folder\shell\open\command\(Default)"),
                field("Details", "contains", "powershell"),
            ),
        ),
        (
            rule(
                "registry_object_created_or_deleted",
                field("TargetObject", "contains", r"\Folder\shell\open\command"),
            ),
            rule("registry_value_set", field("TargetObject", "contains", "DelegateExecute")),
        ),
    ),
    Hunt(
        "delegate-empty",
        "registry",
        "An empty DelegateExecute value is written below the Folder shell handler.",
        (
            "Find an empty DelegateExecute value written under Folder\\shell\\open\\command.",
            "Show the folder shell handler's DelegateExecute value being set to empty.",
            "Locate the empty delegation value accompanying a folder-open handler change.",
        ),
        (
            rule(
                "registry_value_set",
                field("TargetObject", "endswith", r"\DelegateExecute"),
                field("Details", "equals", "(Empty)"),
            ),
        ),
        (
            rule(
                "registry_value_set",
                field("TargetObject", "contains", r"\Folder\shell\open\command"),
            ),
        ),
    ),
    Hunt(
        "service-imagepath",
        "registry",
        "javamtsup ImagePath is set; other values in the same service key are negatives.",
        (
            "Find a registry ImagePath write for the javamtsup service.",
            "Show the executable path being configured for the Java support service.",
            "Locate javamtsup's binary-path registry setting, not its start mode or display name.",
        ),
        (
            rule(
                "registry_value_set",
                field("TargetObject", "endswith", r"\Services\javamtsup\ImagePath"),
            ),
        ),
        (
            rule("registry_value_set", field("TargetObject", "contains", r"\Services\javamtsup")),
            rule("service_installed", field("ServiceName", "equals", "javamtsup")),
        ),
    ),
    Hunt(
        "defender-run",
        "benign-control",
        "A Defender Run-key write is an autostart artifact, "
        "not automatically malicious persistence.",
        (
            "Find WindowsDefender registry writes under CurrentVersion\\Run.",
            "Show Windows Defender configuring its logon autostart Run value.",
            "Locate the Defender startup-entry change "
            "without labeling every Run-key write malicious.",
        ),
        (
            rule(
                "registry_value_set",
                field("TargetObject", "endswith", r"\CurrentVersion\Run\WindowsDefender"),
            ),
        ),
        (REGISTRY,),
    ),
    Hunt(
        "draft-created",
        "file-operation",
        "PowerShell creates Draft.Zip; deletion commands mentioning the archive are not positives.",
        (
            "Find file creation of Draft.Zip by powershell.exe.",
            "Show PowerShell writing the Draft ZIP archive to disk.",
            "Retrieve archive-creation evidence for Draft.Zip, not subsequent deletion activity.",
        ),
        (rule("file_created", PS, field("TargetFilename", "endswith", r"\Draft.Zip")),),
        (rule("process_creation", field("CommandLine", "contains", "Draft.Zip")), FILES),
    ),
    Hunt(
        "monkey-created",
        "file-operation",
        "The monkey.png file creation, not a command reading the bitmap.",
        (
            "Find file-created events for monkey.png in a Downloads directory.",
            "Show the image payload file being written to the user's Downloads folder.",
            "Retrieve the creation of monkey.png rather than later PowerShell commands reading it.",
        ),
        (rule("file_created", field("TargetFilename", "endswith", r"\Downloads\monkey.png")),),
        (rule("process_creation", field("CommandLine", "contains", "monkey.png")),),
    ),
    Hunt(
        "policy-test-file",
        "benign-control",
        "PowerShell creates its __PSScriptPolicyTest .ps1 file; not a malware label.",
        (
            "Find PowerShell file creation for __PSScriptPolicyTest files ending in .ps1.",
            "Show temporary PowerShell script-policy probe files.",
            "Separate the shell's execution-policy test scripts "
            "from arbitrary dropped payload files.",
        ),
        (
            rule(
                "file_created",
                PS,
                field("TargetFilename", "contains", "__PSScriptPolicyTest"),
                field("TargetFilename", "endswith", ".ps1"),
            ),
        ),
        (rule("file_created", PS),),
    ),
    Hunt(
        "powershell-dll-file",
        "file-operation",
        "PowerShell creates a DLL under a temporary directory; not an image-load event.",
        (
            "Find powershell.exe creating .dll files under AppData\\Local\\Temp.",
            "Show PowerShell writing a dynamic library into the user's temporary directory.",
            "Look for a DLL dropped by PowerShell, excluding records that merely load a DLL.",
        ),
        (
            rule(
                "file_created",
                PS,
                field("TargetFilename", "contains", r"\AppData\Local\Temp"),
                field("TargetFilename", "endswith", ".dll"),
            ),
        ),
        (rule("image_loaded", PS), rule("file_created", PS)),
    ),
    Hunt(
        "psexesvc-installed",
        "service-versus-execution",
        "Service installation for PSEXESVC (Security 4697 or System 7045), "
        "not process or registry.",
        (
            "Find service-installation events for PSEXESVC.",
            "Show the PsExec helper being registered as a Windows service.",
            "Retrieve evidence that the remote execution service was installed, not just started.",
        ),
        (rule("service_installed", field("ServiceName", "equals", "PSEXESVC")),),
        (
            rule("process_creation", field("Image|NewProcessName", "endswith", r"\PSEXESVC.exe")),
            rule("registry_value_set", field("TargetObject", "contains", "PSEXESVC")),
        ),
    ),
    Hunt(
        "javamtsup-installed",
        "service-versus-execution",
        "Service installation for javamtsup (Security 4697 or System 7045), not process creation.",
        (
            "Find installation of the javamtsup Windows service.",
            "Show the Java support executable being registered with the service manager.",
            "Locate creation of the Java(TM) Virtual Machine Support Service, not its execution.",
        ),
        (rule("service_installed", field("ServiceName", "equals", "javamtsup")),),
        (
            rule("process_creation", field("Image|NewProcessName", "endswith", r"\javamtsup.exe")),
            rule("registry_value_set", field("TargetObject", "contains", "javamtsup")),
        ),
    ),
    Hunt(
        "psexesvc-credentials",
        "authentication",
        "An explicit-credentials logon by PSEXESVC for pbeesly, not ordinary logon success.",
        (
            "Find explicit-credentials logons by PSEXESVC.exe using the pbeesly account.",
            "Show PsExec's service supplying explicit credentials for pbeesly.",
            "Retrieve credential-use audit events from the remote execution service, "
            "not logon success.",
        ),
        (
            rule(
                "explicit_credentials_logon",
                field("ProcessName", "endswith", r"\PSEXESVC.exe"),
                field("TargetUserName", "equals", "pbeesly"),
            ),
        ),
        (
            rule("successful_logon", field("TargetUserName", "equals", "pbeesly")),
            rule("explicit_credentials_logon"),
        ),
    ),
    Hunt(
        "pbeesly-network-logon",
        "authentication",
        "Successful logon for pbeesly with LogonType 3, not interactive Type 2.",
        (
            "Find successful logons for pbeesly with LogonType 3.",
            "Show successful network logons by pbeesly rather than interactive desktop logons.",
            "Locate pbeesly's authenticated network sessions, "
            "excluding explicit-credential attempts.",
        ),
        (
            rule(
                "successful_logon",
                field("TargetUserName", "equals", "pbeesly"),
                field("LogonType", "equals", "3"),
            ),
        ),
        (
            rule("successful_logon", field("TargetUserName", "equals", "pbeesly")),
            rule("explicit_credentials_logon", field("TargetUserName", "equals", "pbeesly")),
        ),
    ),
    Hunt(
        "psexec-mixed-evidence",
        "mixed-evidence",
        "Retrieve multiple evidence types, not a causal reconstruction of a remote session.",
        (
            "Find both PsExec64.exe process launches and installation events for PSEXESVC.",
            "Show PsExec execution evidence together with registration of its helper service.",
            "Collect the launch and service-install artifacts of PsExec, "
            "without asserting causality.",
        ),
        (
            rule("process_creation", PSEXEC),
            rule("service_installed", field("ServiceName", "equals", "PSEXESVC")),
        ),
        (PROC, rule("service_installed")),
        required_types=("process_creation", "service_installed"),
    ),
    Hunt(
        "lsass-mixed-evidence",
        "mixed-evidence",
        "Retrieve both handle access and remote-thread creation from PowerShell into LSASS.",
        (
            "Find PowerShell-to-LSASS process-access and remote-thread-creation events.",
            "Show both LSASS handle opening and thread injection involving PowerShell.",
            "Collect handle-access and remote-thread evidence "
            "with PowerShell as source and LSASS target.",
        ),
        (rule("process_access|remote_thread_created", SOURCE_PS, TARGET_LSASS),),
        (rule("process_access", SOURCE_LSASS), rule("remote_thread_created")),
        required_types=("process_access", "remote_thread_created"),
    ),
)

ABSENT_HUNTS = (
    Hunt(
        "absent-certutil",
        "no-answer",
        "No matching certutil process in the pinned source.",
        ("Find certutil.exe downloading a file with -urlcache.",) * 3,
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\certutil.exe"),
                field("CommandLine", "contains", "-urlcache"),
            ),
        ),
        (PROC,),
        absent=True,
    ),
    Hunt(
        "absent-shadow-delete",
        "no-answer",
        "No vssadmin delete shadows command in the source.",
        ("Find vssadmin.exe deleting volume shadow copies.",) * 3,
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\vssadmin.exe"),
                field("CommandLine", "contains", "delete shadows"),
            ),
        ),
        (PROC,),
        absent=True,
    ),
    Hunt(
        "absent-mshta",
        "no-answer",
        "No mshta process with an HTTP URL in the source.",
        ("Find mshta.exe executing a remote HTTP application.",) * 3,
        (
            rule(
                "process_creation",
                field("Image|NewProcessName", "endswith", r"\mshta.exe"),
                field("CommandLine", "contains", "http"),
            ),
        ),
        (PROC,),
        absent=True,
    ),
    Hunt(
        "absent-failed-logon",
        "no-answer",
        "No failed-logon event for pbeesly in this snapshot.",
        ("Find failed authentication attempts for the pbeesly account.",) * 3,
        (rule("failed_logon", field("TargetUserName", "equals", "pbeesly")),),
        (rule("successful_logon", field("TargetUserName", "equals", "pbeesly")),),
        absent=True,
    ),
    Hunt(
        "absent-ip",
        "no-answer",
        "No network event has this documentation-range destination IP.",
        ("Find network connections whose destination is exactly 203.0.113.77.",) * 3,
        (rule("network_connection", field("DestinationIp", "equals", "203.0.113.77")),),
        (NET,),
        absent=True,
    ),
    Hunt(
        "absent-service",
        "no-answer",
        "No service-install event names BlueRagTestService.",
        ("Find installation of the BlueRagTestService Windows service.",) * 3,
        (rule("service_installed", field("ServiceName", "equals", "BlueRagTestService")),),
        (rule("service_installed"),),
        absent=True,
    ),
)
