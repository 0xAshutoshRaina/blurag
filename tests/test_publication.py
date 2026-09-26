import copy
import hashlib
import json

import pytest

from blurag.publication import MODELS, SOURCE_SHA256, project_results, render_cases


def fixture():
    query = {
        "id": "example",
        "hunt": "example",
        "query": "Find the public test event.",
        "track": "main",
        "style": "literal",
        "scope": {},
        "apply_filter": False,
    }
    definitions = {"label_revision": 2, "queries": [query]}
    definitions_sha = hashlib.sha256(json.dumps(definitions, sort_keys=True).encode()).hexdigest()
    manifest = {
        "source_sha256": SOURCE_SHA256,
        "source_records": 196081,
        "definitions_sha256": definitions_sha,
        "definitions": definitions,
        "corpus_sha256": "a" * 64,
        "corpus_events": 1,
        "query_count": 1,
        "events": [{"event_uid": "b" * 64, "source_record": 123, "secret_field": "DO_NOT_EXPORT"}],
        "labels": {"example": {"positive_ids": ["b" * 64], "confuser_ids": []}},
    }
    results = {}
    for name in MODELS:
        results[name] = {
            "model": name,
            "definitions_sha256": definitions_sha,
            "corpus_sha256": "a" * 64,
            "run_info": {"input_file": "/private/path/DO_NOT_EXPORT", "secret": "DO_NOT_EXPORT"},
            "results": [
                {
                    **query,
                    "category": "test",
                    "original": {"payload": "DO_NOT_EXPORT"},
                    "metrics": {
                        "relevant_count": 1,
                        "first_relevant_rank": 1,
                        "hit_at_1": 1,
                        "hit_at_5": 1,
                        "hit_at_10": 1,
                        "precision_at_5": 0.2,
                        "recall_at_10": 1,
                        "mrr_at_10": 1,
                        "ndcg_at_10": 1,
                        "unexpected": "DO_NOT_EXPORT",
                    },
                    "top_10": [
                        {
                            "rank": 1,
                            "score": 0.6,
                            "event_uid": "b" * 64,
                            "source_record": 123,
                            "event_type": "process_creation",
                            "evidence_type": "process_creation",
                            "relevant": True,
                            "confuser": False,
                            "evidence": "DO_NOT_EXPORT",
                            "original": {"payload": "DO_NOT_EXPORT"},
                        }
                    ],
                }
            ],
        }
    return manifest, results


def test_public_export_allows_only_metrics_queries_and_source_references():
    manifest, results = fixture()
    public = project_results(manifest, results)
    assert "DO_NOT_EXPORT" not in json.dumps(public)
    assert public["cases"][0]["expected_source_records"] == [123]
    assert public["summary"]["securebert"]["hit_at_5"] == 1
    assert public["cases"][0]["retrievers"]["securebert"]["top_10"][0]["score"] == 0.6
    assert "Find the public test event." in render_cases(public)
    assert "DO_NOT_EXPORT" not in render_cases(public)


def test_export_refuses_non_public_or_changed_inputs():
    manifest, results = fixture()
    with pytest.raises(ValueError, match="pinned public"):
        project_results({**manifest, "source_sha256": "private-source"}, results)
    manifest["definitions"]["queries"][0]["query"] = "Changed query"
    with pytest.raises(ValueError, match="checksum"):
        project_results(manifest, results)


@pytest.mark.parametrize("change", ["query", "row", "relevance", "count", "duplicate"])
def test_export_rejects_mismatched_results(change):
    manifest, results = fixture()
    item = results["securebert"]["results"][0]
    if change == "query":
        item["query"] = "A different query"
    elif change == "row":
        item["top_10"][0]["source_record"] = 999
    elif change == "relevance":
        item["top_10"][0]["relevant"] = False
    elif change == "count":
        item["metrics"]["relevant_count"] = 0
    else:
        results["securebert"]["results"].append(copy.deepcopy(item))
    with pytest.raises(ValueError):
        project_results(manifest, results)
