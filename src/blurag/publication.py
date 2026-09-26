"""Export the pinned benchmark's measurements without copying telemetry text."""

import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA256 = "dce651806007a20f6f4bac806dd6054e3361e0dd57a74ddd2f7cb5665d98c954"
MODELS = ("bm25", "minilm", "securebert")
METRICS = (
    "relevant_count",
    "returned_count",
    "first_relevant_rank",
    "hit_at_1",
    "hit_at_5",
    "hit_at_10",
    "precision_at_5",
    "recall_at_10",
    "mrr_at_10",
    "ndcg_at_10",
    "confusers_in_top_5",
    "candidate_events",
    "required_type_coverage_at_10",
)
HIT_FIELDS = (
    "rank",
    "score",
    "event_uid",
    "source_record",
    "event_type",
    "evidence_type",
    "relevant",
    "confuser",
)
CASE_FIELDS = ("id", "hunt", "query", "track", "style", "scope", "apply_filter", "category")


def project_results(manifest: dict, results: dict[str, dict]) -> dict:
    if manifest["source_sha256"] != SOURCE_SHA256:
        raise ValueError("Only the pinned public OTRF dataset may be exported.")
    definitions_sha = hashlib.sha256(
        json.dumps(manifest["definitions"], sort_keys=True).encode()
    ).hexdigest()
    if definitions_sha != manifest["definitions_sha256"]:
        raise ValueError("Benchmark definitions do not match their checksum.")
    definitions = {case["id"]: case for case in manifest["definitions"]["queries"]}
    event_rows = {event["event_uid"]: event["source_record"] for event in manifest["events"]}
    if len(definitions) != manifest["query_count"] or len(event_rows) != manifest["corpus_events"]:
        raise ValueError("Benchmark inventory contains missing or duplicate entries.")
    projected = {}
    summaries = {}
    fingerprints = {}
    for name in MODELS:
        result = results[name]
        if (
            result["model"] != name
            or result["definitions_sha256"] != definitions_sha
            or result["corpus_sha256"] != manifest["corpus_sha256"]
        ):
            raise ValueError(f"{name} results do not match the frozen fixture.")
        rows = {case["id"]: case for case in result["results"]}
        if len(rows) != len(result["results"]) or set(rows) != set(definitions):
            raise ValueError(f"{name} query inventory does not match the fixture.")
        main = [case["metrics"] for case in result["results"] if case["track"] == "main"]
        if not main:
            raise ValueError("A public comparison needs main-track cases.")
        summaries[name] = {
            "queries": len(main),
            **{
                metric: round(sum(case[metric] for case in main) / len(main), 4)
                for metric in (
                    "hit_at_1",
                    "hit_at_5",
                    "hit_at_10",
                    "precision_at_5",
                    "recall_at_10",
                    "mrr_at_10",
                    "ndcg_at_10",
                )
            },
        }
        fingerprints[name] = {
            key: result["run_info"][key]
            for key in ("model_id", "model_revision", "vector_name")
            if key in result["run_info"]
        }
        for case_id, definition in definitions.items():
            case = rows[case_id]
            if any(case[key] != definition[key] for key in definition):
                raise ValueError(f"{name}/{case_id} no longer matches its exact query definition.")
            labels = manifest["labels"][case_id]
            positive = set(labels["positive_ids"])
            confusers = set(labels["confuser_ids"])
            if not positive.union(confusers).issubset(event_rows):
                raise ValueError(f"{case_id} references evidence outside the fixture.")
            if case["metrics"]["relevant_count"] != len(positive):
                raise ValueError(f"{name}/{case_id} relevant count differs from its labels.")
            if case_id not in projected:
                projected[case_id] = {
                    **{key: case[key] for key in CASE_FIELDS},
                    "expected_source_records": sorted(event_rows[uid] for uid in positive),
                    "confuser_source_records": sorted(event_rows[uid] for uid in confusers),
                    "retrievers": {},
                }
            hits = []
            for rank, hit in enumerate(case["top_10"], 1):
                uid = hit["event_uid"]
                if (
                    uid not in event_rows
                    or hit["source_record"] != event_rows[uid]
                    or hit["rank"] != rank
                    or hit["relevant"] != (uid in positive)
                    or hit["confuser"] != (uid in confusers)
                ):
                    raise ValueError(f"{name}/{case_id} has inconsistent hit evidence.")
                hits.append({key: hit[key] for key in HIT_FIELDS if key in hit})
            if len(hits) > 10 or len({hit["event_uid"] for hit in hits}) != len(hits):
                raise ValueError(f"{name}/{case_id} has duplicate or excess top-ten hits.")
            projected[case_id]["retrievers"][name] = {
                "metrics": {key: case["metrics"][key] for key in METRICS if key in case["metrics"]},
                "top_10": hits,
            }
    return {
        "schema_version": 1,
        "label_revision": manifest["definitions"]["label_revision"],
        "source_sha256": SOURCE_SHA256,
        "source_records": manifest["source_records"],
        "definitions_sha256": definitions_sha,
        "corpus_sha256": manifest["corpus_sha256"],
        "corpus_events": manifest["corpus_events"],
        "query_count": manifest["query_count"],
        "models": fingerprints,
        "summary": summaries,
        "cases": list(projected.values()),
        "publication_policy": (
            "Original measurements, query text, labels, ranks and public-dataset source references "
            "only. No event bodies, command-line excerpts, embeddings, "
            "model weights or local paths."
        ),
    }


def render_cases(public: dict) -> str:
    lines = [
        "# Query results",
        "",
        f"{public['query_count']} queries, {public['corpus_events']} real events, "
        f"label revision {public['label_revision']}.",
        "",
        "Numbers are the first relevant result's rank; lower is better. A dash means "
        "no relevant event exists in the candidate set, not that search returned nothing. "
        "Matches is the number of relevant candidate events.",
        "",
        "[Findings and method](../../EVALUATION.md) / [Full results](results.json)",
    ]
    sections = (
        ("main", "Behavior queries"),
        ("mixed", "Multiple event types"),
        ("no-answer", "Absent behaviors"),
        ("scope", "Host and time scope"),
        ("empty-scope", "Empty scopes"),
        ("robustness", "Short queries and typos"),
    )
    unknown_tracks = {case["track"] for case in public["cases"]} - {track for track, _ in sections}
    if unknown_tracks:
        raise ValueError(f"Unknown query tracks: {sorted(unknown_tracks)}")
    for track, title in sections:
        cases = [case for case in public["cases"] if case["track"] == track]
        if not cases:
            continue
        lines += [
            "",
            f"## {title}",
            "",
            "| Query | Matches | BM25 | MiniLM | Cisco |",
            "|---|---:|---:|---:|---:|",
        ]
        for case in cases:
            query = case["query"]
            if case["scope"]:
                scope = ", ".join(f"{key}={value}" for key, value in case["scope"].items())
                query += f" (filter: {scope})" if case["apply_filter"] else " (no filter)"
            query = (
                query.replace("|", "\\|")
                .replace("\n", " ")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            ranks = [case["retrievers"][name]["metrics"]["first_relevant_rank"] for name in MODELS]
            lines.append(
                f"| {query} | {len(case['expected_source_records'])} | "
                + " | ".join("-" if rank is None else str(rank) for rank in ranks)
                + " |"
            )
    return "\n".join(lines) + "\n"


def export_research(source: Path, destination: Path) -> dict:
    manifest = json.loads((source / "manifest.json").read_text())
    results = {name: json.loads((source / f"{name}-results.json").read_text()) for name in MODELS}
    public = project_results(manifest, results)
    provenance = {
        "source_repository": "https://github.com/OTRF/Security-Datasets",
        "source_revision": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
        "source_archive_member": "apt29_evals_day1_manual_2020-05-01225525.json",
        **{
            key: public[key]
            for key in (
                "source_sha256",
                "source_records",
                "definitions_sha256",
                "corpus_sha256",
                "corpus_events",
                "query_count",
                "label_revision",
            )
        },
        "selected_events": [
            {"event_uid": event["event_uid"], "source_record": event["source_record"]}
            for event in manifest["events"]
        ],
        "input_artifact_sha256": {
            filename: hashlib.sha256((source / filename).read_bytes()).hexdigest()
            for filename in ("manifest.json", *(f"{name}-results.json" for name in MODELS))
        },
    }
    destination.mkdir(parents=True, exist_ok=True)
    for name, value in (("results.json", public), ("provenance.json", provenance)):
        (destination / name).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    (destination / "cases.md").write_text(render_cases(public))
    return {
        "destination": str(destination),
        "queries": public["query_count"],
        "events": public["corpus_events"],
        "files": ["cases.md", "results.json", "provenance.json"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(".blurag/evaluation/relevance-v2"))
    parser.add_argument("--destination", type=Path, default=Path("research/relevance-v2"))
    args = parser.parse_args()
    try:
        report = export_research(args.source, args.destination)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Cannot export research: {exc}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
