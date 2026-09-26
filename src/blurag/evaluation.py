"""Reproducible retrieval evaluation, with source-field labels and exact scoring."""

import hashlib
import heapq
import json
import math
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import numpy as np

from .config import ENCODERS, Settings, file_sha256, write_json
from .embedding import Embedder
from .evaluation_cases import ABSENT_HUNTS, HUNTS, evidence_type
from .events import Event, iter_records, normalize, parse_timestamp
from .store import connect, ingest

SOURCE_SHA256 = "dce651806007a20f6f4bac806dd6054e3361e0dd57a74ddd2f7cb5665d98c954"
ALL_HUNTS = {hunt.id: hunt for hunt in (*HUNTS, *ABSENT_HUNTS)}
SELECTION = {"positives_per_hunt": 8, "confusers_per_hunt": 8, "background_per_group": 6}


@dataclass(frozen=True)
class Case:
    id: str
    hunt: str
    query: str
    track: str
    style: str
    scope: dict[str, str]
    apply_filter: bool = False


def cases() -> list[Case]:
    result = [
        Case(
            id=f"{hunt.id}-{index + 1}",
            hunt=hunt.id,
            query=query,
            track="mixed" if hunt.required_types else "main",
            style=("literal", "paraphrase", "investigative")[index],
            scope={},
        )
        for hunt in HUNTS
        for index, query in enumerate(hunt.queries)
    ]
    result.extend(
        Case(hunt.id, hunt.id, hunt.queries[0], "no-answer", "absent", {}) for hunt in ABSENT_HUNTS
    )
    for hunt_id, query, scope in (
        (
            "pbeesly-network-logon",
            "Find successful network logons by pbeesly on NASHUA.dmevals.local.",
            {"device": "NASHUA.dmevals.local"},
        ),
        (
            "powershell-443",
            "Find PowerShell connections to destination port 443 before 03:00 UTC on May 2, 2020.",
            {"until": "2020-05-02T03:00:00Z"},
        ),
    ):
        for filtered in (False, True):
            suffix = "filtered" if filtered else "text-only"
            result.append(
                Case(f"{hunt_id}-{suffix}", hunt_id, query, "scope", suffix, scope, filtered)
            )
    result.extend(
        (
            Case(
                "empty-device",
                "powershell-443",
                "Find PowerShell connections to port 443.",
                "empty-scope",
                "filtered",
                {"device": "NO-SUCH-ENDPOINT"},
                True,
            ),
            Case(
                "empty-time",
                "powershell-443",
                "Find PowerShell connections to port 443.",
                "empty-scope",
                "filtered",
                {"since": "2026-01-01T00:00:00Z"},
                True,
            ),
        )
    )
    for hunt_id, query in (
        ("powershell-to-lsass", "powershel accessing lsass"),
        ("lsass-remote-thread", "Powershell creates remote thread in LSASS"),
        ("psexesvc-installed", "psexec service instalation"),
        ("powershell-winrm", "PowerShell to WinRM on 10.0.1.6"),
        ("rundll-webdav", "rundll32 WebDAV DavSetCookie"),
        ("folder-command", "folder shell open command hijack powershell"),
    ):
        result.append(Case(f"{hunt_id}-short", hunt_id, query, "robustness", "short", {}))
    return result


def in_scope(event: Event, scope: dict[str, str]) -> bool:
    if "device" in scope and event.metadata["device_key"] != scope["device"].casefold():
        return False
    timestamp = parse_timestamp(event.metadata["timestamp"])
    if "since" in scope and timestamp < parse_timestamp(scope["since"]):
        return False
    if "until" in scope and timestamp >= parse_timestamp(scope["until"]):
        return False
    return True


def _retain(pool: list, event: Event, limit: int) -> None:
    item = (-int(event.uid, 16), event.metadata["source_record"], event)
    if len(pool) < limit:
        heapq.heappush(pool, item)
    else:
        heapq.heappushpop(pool, item)


def _definitions() -> dict:
    return {
        "label_revision": 2,
        "provider_equivalence": "System EventID 7045 and Security 4697 are service installation.",
        "hunts": [asdict(hunt) for hunt in ALL_HUNTS.values()],
        "queries": [asdict(case) for case in cases()],
        "selection": SELECTION,
    }


def prepare_fixture(source: Path, output: Path) -> dict:
    digest = file_sha256(source)
    if digest != SOURCE_SHA256:
        raise ValueError("This benchmark is labeled for the pinned OTRF day-one file only.")
    definitions = _definitions()
    definition_sha = hashlib.sha256(json.dumps(definitions, sort_keys=True).encode()).hexdigest()
    manifest_path = output / "manifest.json"
    corpus_path = output / "corpus.jsonl"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if (
            manifest["definitions_sha256"] != definition_sha
            or manifest["source_sha256"] != digest
            or file_sha256(corpus_path) != manifest["corpus_sha256"]
        ):
            raise ValueError(
                "Benchmark inputs changed. Use a new --output-dir; do not mix results."
            )
        return manifest
    positives, confusers, background, scoped = (defaultdict(list) for _ in range(4))
    source_positive_counts, source_confuser_counts = Counter(), Counter()
    scoped_cases = [case for case in cases() if case.track == "scope" and case.apply_filter]
    source_records = 0
    for number, raw in iter_records(source):
        event = normalize(raw, str(source), number)
        source_records += 1
        _retain(
            background[(event.metadata["device_key"], event.metadata["event_type"])],
            event,
            SELECTION["background_per_group"],
        )
        for hunt in ALL_HUNTS.values():
            if hunt.relevant(event):
                source_positive_counts[hunt.id] += 1
                _retain(positives[hunt.id], event, SELECTION["positives_per_hunt"])
            elif hunt.confusable(event):
                source_confuser_counts[hunt.id] += 1
                if not hunt.absent:
                    _retain(confusers[hunt.id], event, SELECTION["confusers_per_hunt"])
        for case in scoped_cases:
            if ALL_HUNTS[case.hunt].relevant(event) and in_scope(event, case.scope):
                _retain(scoped[case.id], event, SELECTION["positives_per_hunt"])
    for hunt in ALL_HUNTS.values():
        count = source_positive_counts[hunt.id]
        if (not hunt.absent and count == 0) or (hunt.absent and count != 0):
            raise ValueError(f"Invalid source label for {hunt.id}: found {count} expected events.")
    for case in scoped_cases:
        if not scoped[case.id]:
            raise ValueError(f"No source evidence for scoped case {case.id}.")
    chosen = {
        item[2].uid: item[2]
        for pools in (positives, confusers, background, scoped)
        for pool in pools.values()
        for item in pool
    }
    events = sorted(chosen.values(), key=lambda event: event.metadata["source_record"])
    output.mkdir(parents=True, exist_ok=True)
    with corpus_path.open("w") as stream:
        for event in events:
            stream.write(json.dumps(event.raw, ensure_ascii=True, allow_nan=False) + "\n")
    labels = {}
    for case in cases():
        labels[case.id] = {
            "positive_ids": [
                event.uid
                for event in events
                if ALL_HUNTS[case.hunt].relevant(event) and in_scope(event, case.scope)
            ],
            "confuser_ids": [
                event.uid for event in events if ALL_HUNTS[case.hunt].confusable(event)
            ],
        }
        if case.track not in {"no-answer", "empty-scope"} and not labels[case.id]["positive_ids"]:
            raise ValueError(f"The selected corpus has no positive for {case.id}.")
    manifest = {
        "source_file": str(source),
        "source_sha256": digest,
        "source_records": source_records,
        "definitions_sha256": definition_sha,
        "definitions": definitions,
        "corpus_sha256": file_sha256(corpus_path),
        "events": [{"event_uid": event.uid, **event.metadata} for event in events],
        "corpus_events": len(events),
        "unique_normalized_texts": len({event.text for event in events}),
        "source_positive_counts": dict(source_positive_counts),
        "source_confuser_counts": dict(source_confuser_counts),
        "labels": labels,
        "query_count": len(cases()),
    }
    write_json(manifest_path, manifest)
    return manifest


def ranking_metrics(ranked: list[str], relevant: set[str]) -> dict:
    if not relevant:
        return {
            "relevant_count": 0,
            "returned_count": min(10, len(ranked)),
            "first_relevant_rank": None,
        }
    positions = [index + 1 for index, uid in enumerate(ranked) if uid in relevant]
    first = min(positions) if positions else None
    gain = sum(1 / math.log2(rank + 1) for rank in positions if rank <= 10)
    ideal = sum(1 / math.log2(rank + 1) for rank in range(1, min(10, len(relevant)) + 1))
    return {
        "relevant_count": len(relevant),
        "first_relevant_rank": first,
        "hit_at_1": int(first is not None and first <= 1),
        "hit_at_5": int(first is not None and first <= 5),
        "hit_at_10": int(first is not None and first <= 10),
        "precision_at_5": sum(rank <= 5 for rank in positions) / 5,
        "recall_at_10": sum(rank <= 10 for rank in positions) / len(relevant),
        "mrr_at_10": 1 / first if first is not None and first <= 10 else 0.0,
        "ndcg_at_10": gain / ideal,
    }


def exact_event_scores(
    vectors: np.ndarray, query: np.ndarray, event_indexes: np.ndarray, event_count: int
) -> np.ndarray:
    scores = np.full(event_count, -np.inf, dtype=np.float32)
    np.maximum.at(scores, event_indexes, vectors @ query)
    if not np.isfinite(scores).all():
        raise ValueError("Every benchmark event must have at least one finite vector.")
    return scores


class BM25:
    def __init__(self, texts: list[str]):
        self.documents = [Counter(self.tokens(text)) for text in texts]
        self.lengths = np.array([sum(doc.values()) for doc in self.documents])
        self.average_length = float(self.lengths.mean())
        self.frequencies = Counter(term for doc in self.documents for term in doc)

    @staticmethod
    def tokens(text: str) -> list[str]:
        return re.findall(r"[a-z0-9_]+", text.casefold())

    def score(self, query: str) -> np.ndarray:
        scores = np.zeros(len(self.documents), dtype=np.float64)
        normalization = 1.2 * (0.25 + 0.75 * self.lengths / self.average_length)
        for term in set(self.tokens(query)):
            frequency = self.frequencies[term]
            if not frequency:
                continue
            inverse = math.log(1 + (len(self.documents) - frequency + 0.5) / (frequency + 0.5))
            counts = np.array([doc[term] for doc in self.documents])
            scores += inverse * counts * 2.2 / (counts + normalization)
        return scores


def _evidence(event: Event) -> str:
    text = event.text.replace("\r", " ").replace("\n", " ")
    text = re.sub(r"(?i)(\s-p\s+)\S+", r"\1[REDACTED]", text)
    return text[:700]


def evaluate_scores(
    name: str, score_rows: list[np.ndarray], events: list[Event], manifest: dict
) -> dict:
    results = []
    for case, scores in zip(cases(), score_rows, strict=True):
        positive_ids = set(manifest["labels"][case.id]["positive_ids"])
        confuser_ids = set(manifest["labels"][case.id]["confuser_ids"])
        eligible = [
            index
            for index, event in enumerate(events)
            if not case.apply_filter or in_scope(event, case.scope)
        ]
        order = sorted(eligible, key=lambda index: (-float(scores[index]), events[index].uid))
        ranked = [events[index].uid for index in order]
        metrics = ranking_metrics(ranked, positive_ids)
        metrics["confusers_in_top_5"] = sum(uid in confuser_ids for uid in ranked[:5])
        metrics["candidate_events"] = len(eligible)
        required_types = set(ALL_HUNTS[case.hunt].required_types)
        if required_types:
            retrieved_types = {
                evidence_type(events[index])
                for index in order[:10]
                if events[index].uid in positive_ids
            }
            metrics["required_type_coverage_at_10"] = len(retrieved_types & required_types) / len(
                required_types
            )
        results.append(
            {
                **asdict(case),
                "category": ALL_HUNTS[case.hunt].category,
                "metrics": metrics,
                "top_10": [
                    {
                        "rank": rank + 1,
                        "score": float(scores[index]),
                        "event_uid": events[index].uid,
                        "source_record": events[index].metadata["source_record"],
                        "device": events[index].metadata["device"],
                        "event_type": events[index].metadata["event_type"],
                        "evidence_type": evidence_type(events[index]),
                        "timestamp": events[index].metadata["timestamp"],
                        "relevant": events[index].uid in positive_ids,
                        "confuser": events[index].uid in confuser_ids,
                        "evidence": _evidence(events[index]),
                    }
                    for rank, index in enumerate(order[:10])
                ],
            }
        )
    return {"model": name, "results": results}


def aggregate(result: dict, track: str = "main") -> dict:
    rows = [case["metrics"] for case in result["results"] if case["track"] == track]
    if not rows:
        raise ValueError(f"No cases in track {track}.")
    keys = (
        "hit_at_1",
        "hit_at_5",
        "hit_at_10",
        "precision_at_5",
        "recall_at_10",
        "mrr_at_10",
        "ndcg_at_10",
    )
    return {
        "queries": len(rows),
        **{key: round(sum(row[key] for row in rows) / len(rows), 4) for key in keys},
    }


def _load_vectors(settings: Settings, events: list[Event]) -> tuple[np.ndarray, np.ndarray]:
    indexes = {event.uid: index for index, event in enumerate(events)}
    vectors, event_indexes = [], []
    with connect(settings) as client:
        offset = None
        while True:
            points, offset = client.scroll(
                settings.collection,
                offset=offset,
                limit=128,
                with_payload=["event_uid"],
                with_vectors=[settings.encoder.vector_name],
            )
            for point in points:
                uid = point.payload["event_uid"]
                if uid not in indexes:
                    raise ValueError("Benchmark collection contains an unexpected event.")
                vectors.append(point.vector[settings.encoder.vector_name])
                event_indexes.append(indexes[uid])
            if offset is None:
                break
    matrix = np.asarray(vectors, dtype=np.float32)
    if matrix.ndim != 2 or matrix.shape[1] != settings.encoder.dimensions:
        raise ValueError("Invalid benchmark vector matrix.")
    lengths = np.linalg.norm(matrix, axis=1, keepdims=True)
    if not np.isfinite(matrix).all() or np.any(lengths == 0):
        raise ValueError("Invalid benchmark vector values.")
    return matrix / lengths, np.asarray(event_indexes, dtype=np.int64)


def run_benchmark(
    settings: Settings, source: Path, output: Path, prepare_only: bool = False
) -> dict:
    manifest = prepare_fixture(source, output)
    if prepare_only:
        return {
            "queries": manifest["query_count"],
            "corpus_events": manifest["corpus_events"],
            "source_positive_counts": manifest["source_positive_counts"],
            "output_dir": str(output),
        }
    corpus = output / "corpus.jsonl"
    events = [
        normalize(raw, manifest["source_file"], original["source_record"])
        for (_, raw), original in zip(iter_records(corpus), manifest["events"], strict=True)
    ]
    all_results = []
    for name in ("bm25", "minilm", "securebert"):
        result_path = output / f"{name}-results.json"
        if result_path.exists():
            result = json.loads(result_path.read_text())
            if (
                result["definitions_sha256"] != manifest["definitions_sha256"]
                or result["corpus_sha256"] != manifest["corpus_sha256"]
            ):
                raise ValueError("Cached benchmark results do not match the frozen fixture.")
            all_results.append(result)
            continue
        started = time.perf_counter()
        if name == "bm25":
            lexical = BM25([event.text for event in events])
            rows = [lexical.score(case.query) for case in cases()]
            run_info = {"runtime": "BM25, k1=1.2, b=0.75; lowercase alphanumeric tokens"}
        else:
            spec = ENCODERS[name]
            current = replace(
                settings,
                encoder=spec,
                collection=f"blurag_eval_{manifest['definitions_sha256'][:10]}_{name}",
            )
            print(f"Indexing benchmark with {spec.model_id}", file=sys.stderr)
            ingestion = ingest(current, corpus, report_path=output / f"{name}-ingest.json")
            vectors, indexes = _load_vectors(current, events)
            embedder = Embedder(current)
            queries = np.asarray(
                embedder.encode([case.query for case in cases()]), dtype=np.float32
            )
            queries /= np.linalg.norm(queries, axis=1, keepdims=True)
            rows = [exact_event_scores(vectors, query, indexes, len(events)) for query in queries]
            run_info = {
                "model_id": spec.model_id,
                "model_revision": spec.revision,
                "vector_name": spec.vector_name,
                "collection": current.collection,
                "ingestion": ingestion,
            }
        result = evaluate_scores(name, rows, events, manifest)
        result.update(
            {
                "definitions_sha256": manifest["definitions_sha256"],
                "corpus_sha256": manifest["corpus_sha256"],
                "elapsed_seconds": round(time.perf_counter() - started, 3),
                "run_info": run_info,
            }
        )
        write_json(result_path, result)
        all_results.append(result)
        print(f"{name}: {aggregate(result)}", file=sys.stderr)
    write_json(
        output / "comparison.json",
        {
            "manifest": str(output / "manifest.json"),
            "summary": {result["model"]: aggregate(result) for result in all_results},
        },
    )
    write_report(output / "report.md", manifest, all_results, events)
    return {
        "queries": manifest["query_count"],
        "corpus_events": len(events),
        "summary": {result["model"]: aggregate(result) for result in all_results},
        "report": str(output / "report.md"),
    }


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def write_report(path: Path, manifest: dict, results: list[dict], events: list[Event]) -> None:
    lines = [
        "# BluRag retrieval quality evaluation",
        "",
        f"**{manifest['query_count']} queries; {len(HUNTS)} behavior families; "
        f"{manifest['corpus_events']} shared real events.**",
        "",
        "## What was measured",
        "",
        "This is a diagnostic retrieval benchmark, not a detector accuracy or attack-attribution "
        "benchmark. Main queries have **no event-type, hostname or time prefilter**. Both encoders "
        "search precisely the same source events with the existing production normalization and "
        "their own tokenizer/chunk windows. BM25 sees the same normalized text, "
        "without embeddings.",
        "",
        "Labels are explicit predicates on original event fields, fixed before model scoring. "
        "The fixture selects up to eight positives and eight confusers per behavior plus six "
        "background events per device/type and scoped-case positives by content hash. Labels are "
        "then applied to **every** selected event, not just the seed examples. Queries and rules "
        "were authored with knowledge of this lab dataset; this is not an independent held-out "
        "or production-frequency sample. Paraphrases are correlated, not independent trials.",
        "",
        "Vectors are persisted in separate benchmark Qdrant collections. Scoring is exhaustive "
        "cosine similarity, taking the maximum chunk score per original event, with event UID as "
        "the tie-breaker. This isolates embedding/retrieval quality "
        "from approximate-index effects. "
        "It is not a benchmark of production HNSW recall or latency.",
        "",
        "No model is trained or tuned here, no labels/ATT&CK names are added to embedding text, "
        "and no LLM grades the answers. Relevance means evidence matching the stated field rule, "
        "not proof of maliciousness. A source/target match alone never proves credential dumping.",
        "",
        "**Label revision 2:** an evidence audit of the initial run identified System event 7045 "
        "as an alternative valid service-installation record to Security event 4697. Both count "
        "as relevant here, without modifying either encoder's input. The initial v1 run remains "
        "in its own directory; these corrected labels apply to all three retrievers.",
        "",
        "## Existing correctness tests",
        "",
        "Before this work there were 45 parameterized tests. They covered CLI encoder selection; "
        "streaming JSONL/array/Defender input; timestamp validation and precedence; "
        "original evidence "
        "and stable IDs; provider-specific event types; chunk limits and tail preservation; model "
        "checksums and offline-only loading; local database address enforcement; cross-encoder "
        "index isolation; idempotency and interrupted batches; "
        "grouped results; device/time filters; "
        "sampling and extension to full ingestion; real CPU inference, persistence, and forbidden "
        "external connections. **None of those 45 tests measured hunt relevance.**",
        "",
        "## Main retrieval results",
        "",
        "Hit@k is the fraction of queries with at least one field-relevant event in the first k "
        "results. MRR@10 measures the first relevant rank, with zero beyond rank 10. nDCG@10 "
        "measures binary-relevance ranking quality. Recall@10 is relative to the positives in this "
        "selected corpus, **not the full source or all attacks**. Precision@5 is relevant results "
        "divided by five; singleton-answer cases cannot attain 100% P@5.",
        "",
        "| Model | Queries | Hit@1 | Hit@5 | Hit@10 | P@5 | Recall@10 | MRR@10 | nDCG@10 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        summary = aggregate(result)
        values = " | ".join(
            f"{summary[key]:.3f}"
            for key in (
                "hit_at_1",
                "hit_at_5",
                "hit_at_10",
                "precision_at_5",
                "recall_at_10",
                "mrr_at_10",
                "ndcg_at_10",
            )
        )
        lines.append(f"| {result['model']} | {summary['queries']} | {values} |")
    lines += [
        "",
        "Mixed-evidence, no-answer, scope and short-query diagnostics are excluded from "
        "the main average. There are three queries per main family, so families have equal weight.",
        "",
        "## Main categories",
        "",
        "| Category | Model | Queries | Hit@5 | MRR@10 |",
        "|---|---|---:|---:|---:|",
    ]
    for category in sorted({hunt.category for hunt in HUNTS if not hunt.required_types}):
        for result in results:
            subset = [
                item["metrics"]
                for item in result["results"]
                if item["track"] == "main" and item["category"] == category
            ]
            lines.append(
                f"| {category} | {result['model']} | {len(subset)} | "
                f"{np.mean([item['hit_at_5'] for item in subset]):.3f} | "
                f"{np.mean([item['mrr_at_10'] for item in subset]):.3f} |"
            )
    lines += [
        "",
        "## Paraphrases and diagnostic tracks",
        "",
        "| Model | Literal Hit@5 | Paraphrase Hit@5 | Investigative Hit@5 |",
        "|---|---:|---:|---:|",
    ]
    for result in results:
        values = [
            np.mean(
                [
                    item["metrics"]["hit_at_5"]
                    for item in result["results"]
                    if item["track"] == "main" and item["style"] == style
                ]
            )
            for style in ("literal", "paraphrase", "investigative")
        ]
        lines.append(f"| {result['model']} | " + " | ".join(f"{x:.3f}" for x in values) + " |")
    lines += [
        "",
        "The six no-answer queries each have zero field-matching events in the full source. "
        "All return nearest neighbors; none of these retrievers implements abstention. The two "
        "empty-scope controls instead have no eligible records and should return no hits.",
        "",
        "| Mixed-evidence query | BM25 type coverage@10 | MiniLM | Cisco |",
        "|---|---:|---:|---:|",
    ]
    for index, case in enumerate(cases()):
        if case.track == "mixed":
            values = [
                result["results"][index]["metrics"]["required_type_coverage_at_10"]
                for result in results
            ]
            lines.append(f"| {case.id} | " + " | ".join(f"{x:.2f}" for x in values) + " |")
    lines += [
        "",
        "## Every query and first relevant rank",
        "",
        "A dash means no relevant event exists in the selected candidate set. Ranks above ten "
        "are retained so failures are visible rather than silently dropped.",
        "",
        "| Case | Track | Exact query | Positives | BM25 rank | MiniLM rank | Cisco rank |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    by_model = {
        result["model"]: {item["id"]: item for item in result["results"]} for result in results
    }
    for case in cases():
        ranks = [
            by_model[name][case.id]["metrics"]["first_relevant_rank"]
            for name in ("bm25", "minilm", "securebert")
        ]
        lines.append(
            f"| {case.id} | {case.track} | {_md(case.query)} | "
            f"{len(manifest['labels'][case.id]['positive_ids'])} | "
            + " | ".join(str(rank) if rank is not None else "-" for rank in ranks)
            + " |"
        )
    lines += [
        "",
        "## Important interpretation limits",
        "",
        "- No-answer queries have zero matching source events under the explicit field rule. "
        "All three retrievers still return neighbors when candidates exist: there is no calibrated "
        "abstention threshold. Scores are not comparable across the three models.",
        "- Text-only scope cases put host/time in the query, "
        "but the production text representation "
        "keeps those as metadata. Filtered twins gate candidates explicitly. Do not credit the "
        "encoder for a database-filter success.",
        "- Mixed-evidence cases measure retrieval of both required event types at rank ten; they "
        "do not join process GUIDs or establish a causal chain.",
        "- A security-specific training corpus does not establish superior Sysmon retrieval. "
        "Inspect the failures and evidence below, not just the aggregate.",
        "",
        "## Per-case evidence and ranked results",
        "",
    ]
    path.with_name("cases.md").write_text(
        "\n".join(lines[:-2])
        + "\n[Open the detailed expected evidence and ranked results](report.md).\n"
    )
    event_map = {event.uid: event for event in events}
    for case in cases():
        hunt = ALL_HUNTS[case.hunt]
        labels = manifest["labels"][case.id]
        expected_records = [
            event_map[uid].metadata["source_record"] for uid in labels["positive_ids"]
        ]
        lines += [
            f"### {case.id}",
            "",
            f"**Query:** {_md(case.query)}",
            "",
            f"**Ground truth:** {_md(hunt.description)}",
            "",
            f"**Track/style:** {case.track} / {case.style}. "
            f"**Scope:** `{json.dumps(case.scope)}`; applied as filter: {case.apply_filter}.",
            "",
            f"**Matching original source records:** {expected_records or 'None'}. "
            f"Full-source match count for this behavior: "
            f"{manifest['source_positive_counts'].get(hunt.id, 0)}.",
            "",
        ]
        if expected_records:
            exemplar = event_map[labels["positive_ids"][0]]
            lines += [
                f"**Expected evidence example (original record {expected_records[0]}):**",
                "",
                f"> {_md(_evidence(exemplar))}",
                "",
            ]
        for name in ("bm25", "minilm", "securebert"):
            item = by_model[name][case.id]
            lines += [
                f"**{name}:** `{json.dumps(item['metrics'], sort_keys=True)}`",
                "",
                "| Rank | Relevant | Confuser | Source record | Event type | Score | Evidence |",
                "|---:|---|---|---:|---|---:|---|",
            ]
            for hit in item["top_10"][:5]:
                lines.append(
                    f"| {hit['rank']} | {hit['relevant']} | {hit['confuser']} | "
                    f"{hit['source_record']} | {hit['event_type']} | {hit['score']:.4f} | "
                    f"{_md(hit['evidence'])} |"
                )
            if not item["top_10"]:
                lines.append("| - | - | - | - | No eligible candidates | - | - |")
            lines.append("")
    lines += [
        "## Reproduction and provenance",
        "",
        "```sh",
        "./blurag evaluate",
        "```",
        "",
        f"Source: `{manifest['source_file']}` ({manifest['source_records']} events).",
        f"Source SHA-256: `{manifest['source_sha256']}`.",
        f"Fixture definitions SHA-256: `{manifest['definitions_sha256']}`.",
        f"Corpus SHA-256: `{manifest['corpus_sha256']}`.",
        "",
        "The adjacent manifest contains every raw-field predicate, expected/confuser event ID, "
        "source record reference, sampling parameter and exact query. Per-model JSON files retain "
        "the first ten hits, not just the five shown here. `corpus.jsonl` preserves the original "
        "JSON records. Existing production collections are not changed.",
    ]
    path.write_text("\n".join(lines) + "\n")
