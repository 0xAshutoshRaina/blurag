import json
import sys
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from qdrant_client import QdrantClient, models

from .config import EncoderSpec, Settings, write_json
from .embedding import Embedder
from .events import iter_records, normalize, sample_records


def connect(settings: Settings) -> closing[QdrantClient]:
    return closing(
        QdrantClient(url=settings.url, timeout=120, check_compatibility=False, trust_env=False)
    )


def ensure_collection(client: QdrantClient, settings: Settings, *, create: bool = False) -> None:
    encoder = settings.encoder
    exists = client.collection_exists(settings.collection)
    if not exists:
        if not create:
            raise ValueError(
                f"Collection {settings.collection!r} does not exist. Ingest logs first."
            )
        client.create_collection(
            collection_name=settings.collection,
            vectors_config={
                encoder.vector_name: models.VectorParams(
                    size=encoder.dimensions, distance=models.Distance.COSINE
                )
            },
            on_disk_payload=True,
        )
    config = client.get_collection(settings.collection).config.params.vectors
    if (
        not isinstance(config, dict)
        or set(config) != {encoder.vector_name}
        or config[encoder.vector_name].size != encoder.dimensions
        or config[encoder.vector_name].distance != models.Distance.COSINE
    ):
        raise ValueError("Collection embedding/pipeline configuration does not match this PoC.")
    if create:
        for key in ("event_uid", "device", "device_key", "event_id", "event_type", "channel"):
            client.create_payload_index(
                settings.collection, key, field_schema=models.PayloadSchemaType.KEYWORD, wait=True
            )
        client.create_payload_index(
            settings.collection,
            "timestamp",
            field_schema=models.PayloadSchemaType.DATETIME,
            wait=True,
        )
        client.create_payload_index(
            settings.collection,
            "chunk_index",
            field_schema=models.PayloadSchemaType.INTEGER,
            wait=True,
        )


def point_id(event_uid: str, chunk_index: int, encoder: EncoderSpec) -> str:
    return str(uuid5(NAMESPACE_URL, f"blurag:{encoder.vector_name}:{event_uid}:{chunk_index}"))


def ingest(
    settings: Settings,
    path: Path,
    *,
    input_format: str = "jsonl",
    limit: int | None = None,
    batch_size: int = 128,
    sample_per_group: int | None = None,
    report_path: Path | None = None,
) -> dict:
    if batch_size < 1 or (limit is not None and limit < 1):
        raise ValueError("Batch size and record limit must be positive.")
    if not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")
    if sample_per_group is not None and limit is not None:
        raise ValueError("Choose either a record limit or stratified sampling, not both.")
    started = time.perf_counter()
    records = (
        sample_records(path, input_format, sample_per_group)
        if sample_per_group is not None
        else iter_records(path, input_format)
    )
    embedder = Embedder(settings)
    metrics = {
        "input_file": str(path),
        "collection": settings.collection,
        "model": settings.encoder.model_id,
        "dimensions": settings.encoder.dimensions,
        "records_read": 0,
        "chunks_seen": 0,
        "points_written": 0,
        "points_already_present": 0,
        "embedding_seconds": 0.0,
        "limit": limit,
        "sample_per_device_event_type": sample_per_group,
    }
    pending = {}
    with connect(settings) as client:
        ensure_collection(client, settings, create=True)

        def flush() -> None:
            if not pending:
                return
            existing = {
                str(point.id)
                for point in client.retrieve(
                    settings.collection,
                    ids=list(pending),
                    with_payload=False,
                    with_vectors=False,
                )
            }
            metrics["points_already_present"] += len(existing)
            new_points = {key: value for key, value in pending.items() if key not in existing}
            if new_points:
                texts = list(dict.fromkeys(value["text"] for value in new_points.values()))
                encode_started = time.perf_counter()
                vectors = dict(zip(texts, embedder.encode(texts), strict=True))
                metrics["embedding_seconds"] += time.perf_counter() - encode_started
                client.upsert(
                    settings.collection,
                    points=[
                        models.PointStruct(
                            id=key,
                            vector={settings.encoder.vector_name: vectors[payload["text"]]},
                            payload=payload,
                        )
                        for key, payload in new_points.items()
                    ],
                    wait=True,
                )
                metrics["points_written"] += len(new_points)
            pending.clear()
            if metrics["chunks_seen"] % (batch_size * 20) == 0:
                print(json.dumps(metrics), file=sys.stderr)

        for record_number, raw in records:
            try:
                event = normalize(raw, str(path), record_number)
                chunks = embedder.chunks(event.text)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:record {record_number}: {exc} "
                    f"Earlier batches remain stored; fix the input and rerun safely."
                ) from exc
            metrics["records_read"] += 1
            for index, text in enumerate(chunks):
                metrics["chunks_seen"] += 1
                pending[point_id(event.uid, index, settings.encoder)] = {
                    **event.metadata,
                    "chunk_index": index,
                    "chunk_count": len(chunks),
                    "text": text,
                    "original": event.raw,
                }
                if len(pending) >= batch_size:
                    flush()
            if limit is not None and metrics["records_read"] >= limit:
                break
        flush()
        if not metrics["records_read"]:
            raise ValueError("No events were read. Check the input file and --format.")
        metrics["collection_points"] = client.count(settings.collection, exact=True).count
    metrics["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    metrics["embedding_seconds"] = round(metrics["embedding_seconds"], 3)
    write_json(
        report_path or settings.home / "reports" / f"{settings.encoder.key}-last-ingest.json",
        metrics,
    )
    return metrics


def make_filter(
    *,
    device: str | None = None,
    event_id: str | None = None,
    event_type: str | None = None,
    channel: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> models.Filter | None:
    if any(value is not None and value.tzinfo is None for value in (since, until)):
        raise ValueError("Time filters must include a timezone.")
    if since and until and since >= until:
        raise ValueError("--since must be earlier than --until.")
    conditions = []
    for key, value in (
        ("device_key", device.casefold() if device is not None else None),
        ("event_id", event_id),
        ("event_type", event_type),
        ("channel", channel),
    ):
        if value is not None:
            if not value.strip():
                raise ValueError(f"Filter {key} must not be empty.")
            conditions.append(models.FieldCondition(key=key, match=models.MatchValue(value=value)))
    if since or until:
        conditions.append(
            models.FieldCondition(key="timestamp", range=models.DatetimeRange(gte=since, lt=until))
        )
    return models.Filter(must=conditions) if conditions else None


def search(
    settings: Settings,
    query: str,
    *,
    top_k: int = 5,
    include_raw: bool = False,
    **filters,
) -> dict:
    if top_k < 1:
        raise ValueError("--top-k must be positive.")
    query_filter = make_filter(**filters)
    started = time.perf_counter()
    embedder = Embedder(settings)
    vector = embedder.query(query)
    model_seconds = time.perf_counter() - started
    with connect(settings) as client:
        ensure_collection(client, settings)
        search_started = time.perf_counter()
        response = client.query_points_groups(
            collection_name=settings.collection,
            query=vector,
            using=settings.encoder.vector_name,
            group_by="event_uid",
            group_size=1,
            limit=top_k,
            query_filter=query_filter,
            with_payload=True
            if include_raw
            else models.PayloadSelectorExclude(exclude=["original"]),
        )
        search_seconds = time.perf_counter() - search_started
    hits = []
    for group in response.groups:
        point = group.hits[0]
        if point.payload is None:
            raise ValueError("Qdrant returned a search hit without its evidence payload.")
        hits.append({"score": point.score, **point.payload})
    return {
        "model": settings.encoder.model_id,
        "collection": settings.collection,
        "query": query,
        "filters": query_filter.model_dump(mode="json", exclude_none=True)
        if query_filter
        else None,
        "hits": hits,
        "model_load_and_query_embedding_seconds": round(model_seconds, 4),
        "database_search_seconds": round(search_seconds, 4),
        "total_seconds": round(time.perf_counter() - started, 4),
        "note": "Cosine similarity is not threat probability. Each result is a unique event.",
    }


def show_event(settings: Settings, event_uid: str) -> dict:
    with connect(settings) as client:
        ensure_collection(client, settings)
        records, _ = client.scroll(
            settings.collection,
            scroll_filter=models.Filter(
                must=[
                    models.FieldCondition(key="event_uid", match=models.MatchValue(value=event_uid))
                ]
            ),
            limit=1,
            with_payload=True,
            with_vectors=False,
        )
    if not records:
        raise ValueError(f"Event not found: {event_uid}")
    if records[0].payload is None:
        raise ValueError("Qdrant returned an event without its evidence payload.")
    return records[0].payload


def status(settings: Settings) -> dict:
    with connect(settings) as client:
        ensure_collection(client, settings)
        info = client.get_collection(settings.collection)
        points = client.count(settings.collection, exact=True).count
        devices = client.facet(settings.collection, key="device", limit=100, exact=True)
        events = client.count(
            settings.collection,
            count_filter=models.Filter(
                must=[models.FieldCondition(key="chunk_index", match=models.MatchValue(value=0))]
            ),
            exact=True,
        ).count
    return {
        "collection": settings.collection,
        "model": settings.encoder.model_id,
        "dimensions": settings.encoder.dimensions,
        "status": info.status,
        "unique_events": events,
        "points": points,
        "indexed_vectors": info.indexed_vectors_count,
        "devices": [hit.model_dump() for hit in devices.hits],
        "note": (
            "Point and facet counts count chunks. indexed_vectors counts HNSW entries; "
            "small collections remain searchable without HNSW."
        ),
    }
