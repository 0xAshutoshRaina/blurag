import json
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from qdrant_client import QdrantClient, models

from blurag import store
from blurag.config import MINILM, SECUREBERT, Settings
from blurag.events import normalize

pytestmark = pytest.mark.filterwarnings("ignore:Payload indexes have no effect in the local Qdrant")


def sample(device, event_id, timestamp):
    return {
        "Hostname": device,
        "EventID": event_id,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Timestamp": timestamp,
        "Image": "powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
    }


class FakeEmbedder:
    def __init__(self, settings):
        self.dimensions = settings.encoder.dimensions

    def chunks(self, text):
        return [text, text + "\nSecond chunk"]

    def encode(self, texts):
        return [[1.0] + [0.0] * (self.dimensions - 1) for _ in texts]

    def query(self, text):
        return self.encode([text])[0]


@pytest.fixture(params=[MINILM, SECUREBERT], ids=["minilm", "securebert"])
def store_context(tmp_path, monkeypatch, request):
    settings = Settings(tmp_path, "http://localhost:6333", "test_events", encoder=request.param)
    client = QdrantClient(":memory:")
    monkeypatch.setattr(store, "connect", lambda _: nullcontext(client))
    monkeypatch.setattr(store, "Embedder", FakeEmbedder)
    yield settings, client
    client.close()


def test_ingestion_is_idempotent_and_grouped_results_are_filtered(store_context, tmp_path):
    settings, client = store_context
    records = [
        sample("ALPHA", 1, "2020-05-02T02:00:00Z"),
        sample("BETA", 1, "2020-05-02T02:00:00Z"),
        sample("ALPHA", 1, "2020-05-02T03:00:00Z"),
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in records))
    first = store.ingest(settings, path, batch_size=2)
    second = store.ingest(settings, path, batch_size=2)
    assert first["records_read"] == 3
    assert first["points_written"] == 6
    assert second["points_written"] == 0
    assert second["points_already_present"] == 6
    assert client.count(settings.collection).count == 6
    assert store.status(settings)["unique_events"] == 3
    result = store.search(
        settings,
        "PowerShell",
        device="alpha",
        event_id="1",
        since=datetime(2020, 5, 2, 2, tzinfo=UTC),
        until=datetime(2020, 5, 2, 3, tzinfo=UTC),
        include_raw=True,
    )
    assert len(result["hits"]) == 1
    assert result["hits"][0]["original"] == records[0]
    uid = normalize(records[0], str(path), 1).uid
    assert store.show_event(settings, uid)["original"] == records[0]
    assert store.search(settings, "PowerShell", device="does-not-exist")["hits"] == []


def test_collection_configuration_is_never_silently_replaced(store_context):
    settings, client = store_context
    client.create_collection(
        settings.collection,
        vectors_config={
            "wrong_model": models.VectorParams(size=8, distance=models.Distance.COSINE)
        },
    )
    with pytest.raises(ValueError, match="does not match"):
        store.ensure_collection(client, settings, create=True)
    assert "wrong_model" in client.get_collection(settings.collection).config.params.vectors


def test_encoders_cannot_query_or_append_to_each_others_collection(store_context):
    settings, client = store_context
    store.ensure_collection(client, settings, create=True)
    other = replace(settings, encoder=SECUREBERT if settings.encoder == MINILM else MINILM)
    with pytest.raises(ValueError, match="does not match"):
        store.ensure_collection(client, other, create=True)
    assert store.point_id("event", 0, MINILM) != store.point_id("event", 0, SECUREBERT)


def test_invalid_time_range_is_rejected():
    time = datetime(2020, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="earlier"):
        store.make_filter(since=time, until=time)


def test_empty_device_and_naive_boundaries_are_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        store.make_filter(device="")
    with pytest.raises(ValueError, match="timezone"):
        store.make_filter(since=datetime(2020, 1, 1))


def test_empty_input_is_not_reported_as_success(store_context, tmp_path):
    settings, _ = store_context
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    with pytest.raises(ValueError, match="No events"):
        store.ingest(settings, path)


def test_bad_record_names_the_failure_and_retains_committed_batches(store_context, tmp_path):
    settings, client = store_context
    path = tmp_path / "partial.jsonl"
    path.write_text(json.dumps(sample("ALPHA", 1, "2020-01-01T00:00:00Z")) + "\n{}\n")
    with pytest.raises(ValueError, match="record 2.*Earlier batches remain"):
        store.ingest(settings, path, batch_size=2)
    assert client.count(settings.collection).count == 2


def test_full_ingestion_can_extend_a_sample_without_losing_evidence(store_context, tmp_path):
    settings, client = store_context
    records = [sample("ALPHA", 1, f"2020-01-01T00:00:0{second}Z") for second in range(5)]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in records))
    selected = store.ingest(settings, path, sample_per_group=2)
    assert selected["records_read"] == 2
    assert selected["points_written"] == 4
    complete = store.ingest(settings, path)
    assert complete["points_written"] == 6
    assert complete["collection_points"] == 10
    assert store.status(settings)["unique_events"] == 5
    with pytest.raises(ValueError, match="not both"):
        store.ingest(settings, path, limit=1, sample_per_group=1)
