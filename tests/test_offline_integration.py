import json
import os
import socket
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import numpy as np
import pytest

from blurag import store
from blurag.config import MINILM, SECUREBERT, Settings
from blurag.embedding import Embedder

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("BLURAG_RUN_INTEGRATION") != "1",
        reason="Set BLURAG_RUN_INTEGRATION=1 after preparing the model and starting Qdrant.",
    ),
]


@pytest.mark.parametrize("encoder", [MINILM, SECUREBERT], ids=["minilm", "securebert"])
def test_real_cpu_embeddings_persistence_filters_and_no_external_connections(
    tmp_path, monkeypatch, encoder
):
    base = Settings.from_env(f"blurag_test_{uuid4().hex}", encoder=encoder.key)
    settings = replace(base, home=tmp_path / "home")
    settings.home.mkdir()
    settings.model_dir.symlink_to(base.model_dir.resolve(), target_is_directory=True)
    allowed = {"127.0.0.1", "::1", socket.gethostbyname("qdrant")}
    attempted_external_connections = []
    original_connect = socket.socket.connect

    def offline_connect(sock, address):
        if isinstance(address, tuple) and address[0] not in allowed:
            attempted_external_connections.append(address)
            raise AssertionError(f"Unexpected external connection: {address}")
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", offline_connect)
    embedder = Embedder(settings)
    vectors = embedder.encode(["PowerShell process creation", "Registry value changed"])
    assert np.asarray(vectors).shape == (2, encoder.dimensions)
    assert np.linalg.norm(vectors, axis=1) == pytest.approx([1.0, 1.0], abs=1e-5)
    assert not np.allclose(vectors[0], vectors[1])
    with pytest.raises(ValueError, match="token window"):
        embedder.query("process " * (encoder.max_tokens + 1))
    if encoder == SECUREBERT:
        assert str(embedder.model.device) == "cpu"
        assert embedder.model[1].pooling_mode_mean_tokens
        assert not embedder.model[0].auto_model.config.reference_compile
    monkeypatch.setattr(store, "Embedder", lambda _: embedder)
    records = [
        {
            "Hostname": "ALPHA",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1,
            "Timestamp": "2020-05-02T02:00:00Z",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -NoProfile " + "Get-Process; " * 400,
        },
        {
            "Hostname": "BETA",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1,
            "Timestamp": "2020-05-02T02:00:00Z",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -NoProfile",
        },
        {
            "Hostname": "ALPHA",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 13,
            "Timestamp": "2020-05-02T03:00:00Z",
            "TargetObject": r"HKLM\Software\Example",
            "Details": "DWORD (0x00000001)",
        },
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in records))
    try:
        first = store.ingest(settings, path, batch_size=8)
        assert first["points_written"] > first["records_read"]
        second = store.ingest(settings, path, batch_size=8)
        assert second["points_written"] == 0
        assert second["collection_points"] == first["collection_points"]
        assert store.status(settings)["unique_events"] == len(records)
        result = store.search(
            settings,
            "PowerShell process creation",
            device="alpha",
            event_type="process_creation",
            since=datetime(2020, 5, 2, 2, tzinfo=UTC),
            until=datetime(2020, 5, 2, 3, tzinfo=UTC),
            include_raw=True,
        )
        assert len(result["hits"]) == 1
        assert result["hits"][0]["original"] == records[0]
        assert store.show_event(settings, result["hits"][0]["event_uid"])["original"] == records[0]
        assert store.search(settings, "PowerShell", device="missing-host")["hits"] == []
        assert attempted_external_connections == []
    finally:
        with store.connect(settings) as client:
            if client.collection_exists(settings.collection):
                client.delete_collection(settings.collection)
