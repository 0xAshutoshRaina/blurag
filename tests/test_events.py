import json
from collections import Counter
from datetime import UTC, datetime

import pytest

from blurag.events import iter_records, normalize, parse_timestamp, sample_records


def sysmon_event(**overrides):
    return {
        "EventID": 1,
        "Hostname": "WORKSTATION.example",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": "2020-05-02 02:55:23.551",
        "@timestamp": "2020-05-02T02:55:26.493Z",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
        **overrides,
    }


def test_normalization_preserves_evidence_and_uses_event_utc_time():
    raw = sysmon_event()
    result = normalize(raw, "data/logs.jsonl", 12)
    assert result.metadata["timestamp"] == "2020-05-02T02:55:23.551000Z"
    assert result.metadata["timestamp_field"] == "UtcTime"
    assert result.metadata["event_type"] == "process_creation"
    assert result.metadata["device_key"] == "workstation.example"
    assert result.metadata["source_record"] == 12
    assert result.raw == raw
    assert "powershell.exe -NoProfile" in result.text
    assert "WORKSTATION" not in result.text
    assert "2020" not in result.text
    assert normalize(dict(reversed(list(raw.items()))), "elsewhere.jsonl", 1).uid == result.uid


def test_sysmon_semantics_do_not_apply_to_unrelated_event_ids():
    result = normalize(sysmon_event(Channel="Security", EventID=1), "test", 1)
    assert result.metadata["event_type"] == "security_event"


def test_defender_export_fields():
    raw = {
        "Timestamp": "2025-01-01T03:00:00+03:00",
        "DeviceId": "device-123",
        "DeviceName": "server.example",
        "ActionType": "ProcessCreated",
        "ProcessCommandLine": "whoami.exe",
        "FileName": "whoami.exe",
    }
    result = normalize(raw, "export.json", 1)
    assert result.metadata["device_id"] == "device-123"
    assert result.metadata["timestamp"] == "2025-01-01T00:00:00Z"
    assert result.metadata["event_type"] == "ProcessCreated"
    assert "whoami.exe" in result.text


def test_windows_device_name_can_be_a_disk_not_a_hostname():
    raw = sysmon_event(Channel="System", DeviceName=r"\Device\HarddiskVolume2")
    assert normalize(raw, "test", 1).metadata["device"] == "WORKSTATION.example"


def test_message_only_evidence_is_not_discarded():
    raw = sysmon_event(Channel="Microsoft-Windows-PowerShell/Operational", EventID=4104)
    raw["Message"] = "A script block invoked Get-Process."
    result = normalize(raw, "test", 1)
    assert raw["Message"] in result.text
    assert result.metadata["event_type"] == "powershell_script_block"


@pytest.mark.parametrize(
    "raw,match",
    [
        ({"UtcTime": "2020-01-01 00:00:00"}, "Missing device"),
        ({"Hostname": "host"}, "Missing UTC timestamp"),
        ({"Hostname": "host", "Timestamp": "2020-01-01 00:00:00"}, "timezone"),
        (sysmon_event(CommandLine={"bad": "shape"}), "must be a scalar"),
    ],
)
def test_invalid_records_fail_explicitly(raw, match):
    with pytest.raises(ValueError, match=match):
        normalize(raw, "test", 1)


def test_timestamp_boundaries_require_timezone():
    assert parse_timestamp("2020-01-01T02:00:00+02:00") == datetime(2020, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="timezone"):
        parse_timestamp("2020-01-01")


@pytest.mark.parametrize("input_format", ["jsonl", "json-array", "defender"])
def test_input_formats(tmp_path, input_format):
    records = [sysmon_event(), sysmon_event(EventID=3)]
    path = tmp_path / "events.json"
    if input_format == "jsonl":
        path.write_text("\n".join(json.dumps(value) for value in records))
    elif input_format == "json-array":
        path.write_text(json.dumps(records))
    else:
        path.write_text(json.dumps({"Schema": [], "Results": records}))
    assert list(iter_records(path, input_format)) == list(enumerate(records, 1))


def test_jsonl_errors_report_the_physical_line(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text("\n" + json.dumps(sysmon_event()) + "\nnot json\n")
    with pytest.raises(ValueError, match=r":3: invalid JSON"):
        list(iter_records(path))


def test_jsonl_rejects_non_object_rows(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text("[]\n")
    with pytest.raises(ValueError, match="expected an event object"):
        list(iter_records(path))


def test_sample_covers_groups_deterministically_and_keeps_original_record_numbers(tmp_path):
    records = [
        sysmon_event(Hostname=device, EventID=event_id, RecordNumber=number)
        for device in ("ALPHA", "BETA")
        for event_id in (1, 3)
        for number in range(10)
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in records))
    selected = sample_records(path, "jsonl", 2)
    assert selected == sample_records(path, "jsonl", 2)
    assert len(selected) == 8
    assert Counter((raw["Hostname"], raw["EventID"]) for _, raw in selected) == {
        ("ALPHA", 1): 2,
        ("ALPHA", 3): 2,
        ("BETA", 1): 2,
        ("BETA", 3): 2,
    }
    assert all(records[number - 1] == raw for number, raw in selected)
    assert sample_records(path, "jsonl", 100) == list(enumerate(records, 1))
    with pytest.raises(ValueError, match="positive"):
        sample_records(path, "jsonl", 0)
