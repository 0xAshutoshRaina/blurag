import hashlib
import heapq
import json
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ijson

SYSMON_TYPES = {
    "1": "process_creation",
    "2": "file_creation_time_changed",
    "3": "network_connection",
    "4": "sysmon_service_state",
    "5": "process_terminated",
    "6": "driver_loaded",
    "7": "image_loaded",
    "8": "remote_thread_created",
    "9": "raw_disk_read",
    "10": "process_access",
    "11": "file_created",
    "12": "registry_object_created_or_deleted",
    "13": "registry_value_set",
    "14": "registry_object_renamed",
    "15": "file_stream_created",
    "17": "named_pipe_created",
    "18": "named_pipe_connected",
    "19": "wmi_event_filter",
    "20": "wmi_event_consumer",
    "21": "wmi_event_binding",
    "22": "dns_query",
    "23": "file_deleted",
    "25": "process_tampering",
    "26": "file_deleted",
}
SECURITY_TYPES = {
    "4624": "successful_logon",
    "4625": "failed_logon",
    "4634": "logoff",
    "4648": "explicit_credentials_logon",
    "4672": "special_privileges_assigned",
    "4688": "process_creation",
    "4689": "process_terminated",
    "4697": "service_installed",
    "4698": "scheduled_task_created",
    "4720": "user_account_created",
}
TEXT_FIELDS = (
    ("Executable", ("Image", "NewProcessName", "FileName", "Application")),
    ("Command line", ("CommandLine", "ProcessCommandLine", "HostApplication")),
    ("Parent executable", ("ParentImage", "InitiatingProcessFileName", "ParentProcessName")),
    ("Parent command line", ("ParentCommandLine", "InitiatingProcessCommandLine")),
    ("Source process", ("SourceImage",)),
    ("Target process", ("TargetImage",)),
    ("User", ("User", "AccountName", "SubjectUserName")),
    ("Target user", ("TargetUserName",)),
    ("File path", ("TargetFilename", "FolderPath", "ObjectName")),
    ("Registry target", ("TargetObject", "RegistryKey")),
    ("Registry value", ("Details", "RegistryValueData")),
    ("Destination IP", ("DestinationIp", "RemoteIP")),
    ("Destination hostname", ("DestinationHostname", "RemoteUrl")),
    ("Destination port", ("DestinationPort", "RemotePort")),
    ("Source IP", ("SourceIp", "LocalIP", "IpAddress")),
    ("Source port", ("SourcePort", "LocalPort")),
    ("Protocol", ("Protocol",)),
    ("DNS query", ("QueryName",)),
    ("DNS results", ("QueryResults",)),
    ("Pipe", ("PipeName",)),
    ("Access mask", ("GrantedAccess", "AccessMask")),
    ("Loaded image", ("ImageLoaded",)),
    ("Hashes", ("Hashes", "SHA256", "SHA1")),
    ("Logon type", ("LogonType",)),
    ("Script block", ("ScriptBlockText",)),
)


def first_value(raw: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = raw.get(name)
        if value is not None and value != "" and value != "-":
            if not isinstance(value, (str, int, float, bool)):
                raise ValueError(f"{name} must be a scalar value.")
            return str(value)
    return None


def parse_timestamp(value: str, *, allow_naive_utc: bool = False) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        if not allow_naive_utc:
            raise ValueError(f"Timestamp needs a timezone (use Z for UTC): {value!r}")
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class Event:
    uid: str
    text: str
    metadata: dict[str, Any]
    raw: dict[str, Any]


def normalize(raw: dict[str, Any], source: str, record: int) -> Event:
    # Windows System events can use DeviceName for a driver or disk, not a host.
    device = first_value(raw, "Hostname", "Computer", "ComputerName", "DeviceName", "DeviceId")
    if not device:
        raise ValueError("Missing device: expected DeviceName, Hostname, Computer, or DeviceId.")
    timestamp = None
    timestamp_field = None
    for field in ("UtcTime", "Timestamp", "@timestamp"):
        value = first_value(raw, field)
        if value:
            timestamp = parse_timestamp(value, allow_naive_utc=field == "UtcTime")
            timestamp_field = field
            break
    if timestamp is None:
        raise ValueError("Missing UTC timestamp: expected UtcTime, Timestamp, or @timestamp.")
    event_id = first_value(raw, "EventID", "EventId")
    channel = first_value(raw, "Channel", "SourceName") or ""
    action = first_value(raw, "ActionType")
    if action:
        event_type = action
    elif "sysmon" in channel.lower():
        event_type = SYSMON_TYPES.get(event_id, "sysmon_event")
    elif channel.lower() == "security":
        event_type = SECURITY_TYPES.get(event_id, "security_event")
    elif "powershell" in channel.lower():
        event_type = "powershell_script_block" if event_id == "4104" else "powershell_event"
    else:
        event_type = "windows_event"
    parts = [f"Event: {event_type.replace('_', ' ')}."]
    selected = set()
    for label, names in TEXT_FIELDS:
        value = first_value(raw, *names)
        if value:
            parts.append(f"{label}: {value}")
            selected.update(name for name in names if name in raw)
    # Sysmon messages duplicate their structured fields; other providers often keep
    # their useful evidence only in Message. The complete original is always retained.
    if "sysmon" not in channel.lower() or not selected:
        message = first_value(raw, "Message", "RenderedDescription")
        if message:
            parts.append(f"Message: {message}")
    canonical = json.dumps(
        raw, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )
    uid = hashlib.sha256(canonical.encode()).hexdigest()
    metadata = {
        "event_uid": uid,
        "device": device,
        "device_key": device.casefold(),
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "timestamp_field": timestamp_field,
        "event_type": event_type,
        "channel": channel,
        "source_file": source,
        "source_record": record,
    }
    if event_id is not None:
        metadata["event_id"] = event_id
    device_id = first_value(raw, "DeviceId")
    if device_id:
        metadata["device_id"] = device_id
    return Event(uid, "\n".join(parts), metadata, raw)


def iter_records(path: Path, input_format: str = "jsonl") -> Iterator[tuple[int, dict]]:
    with path.open("rb") as stream:
        if input_format == "jsonl":
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{number}: expected an event object.")
                yield number, value
        else:
            prefix = "item" if input_format == "json-array" else "Results.item"
            for number, value in enumerate(ijson.items(stream, prefix, use_float=True), 1):
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:record {number}: expected an event object.")
                yield number, value


def sample_records(path: Path, input_format: str, per_group: int) -> list[tuple[int, dict]]:
    if per_group < 1:
        raise ValueError("Sample size per group must be positive.")
    groups = defaultdict(list)
    for number, raw in iter_records(path, input_format):
        try:
            event = normalize(raw, str(path), number)
        except ValueError as exc:
            raise ValueError(f"{path}:record {number}: {exc}") from exc
        key = (event.metadata["device_key"], event.metadata["event_type"])
        # Lowest content hashes give a reproducible sample across the whole file,
        # rather than only its earliest events. Keep original record references.
        candidate = (-int(event.uid, 16), number, raw)
        if len(groups[key]) < per_group:
            heapq.heappush(groups[key], candidate)
        else:
            heapq.heappushpop(groups[key], candidate)
    return sorted(
        ((number, raw) for group in groups.values() for _, number, raw in group),
        key=lambda item: item[0],
    )
