import numpy as np
import pytest

from blurag import evaluation
from blurag.evaluation import (
    BM25,
    Case,
    cases,
    evaluate_scores,
    exact_event_scores,
    in_scope,
    ranking_metrics,
)
from blurag.evaluation_cases import HUNTS
from blurag.events import normalize


def event(**fields):
    return normalize(
        {
            "Hostname": "ALPHA",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 10,
            "UtcTime": "2020-05-02 03:00:00",
            **fields,
        },
        "source.jsonl",
        1,
    )


def test_case_inventory_is_large_and_unique_without_main_prefilters():
    catalog = cases()
    assert len(catalog) == 120
    assert len({case.id for case in catalog}) == len(catalog)
    assert sum(case.track == "main" for case in catalog) == 96
    assert all(not case.scope and not case.apply_filter for case in catalog if case.track == "main")


def test_direction_labels_distinguish_source_from_target():
    hunts = {hunt.id: hunt for hunt in HUNTS}
    forward = event(SourceImage=r"C:\powershell.exe", TargetImage=r"C:\lsass.exe")
    reverse = event(SourceImage=r"C:\lsass.exe", TargetImage=r"C:\powershell.exe")
    assert hunts["powershell-to-lsass"].relevant(forward)
    assert not hunts["powershell-to-lsass"].relevant(reverse)
    assert hunts["powershell-to-lsass"].confusable(reverse)
    assert hunts["lsass-to-powershell"].relevant(reverse)


def test_exact_access_rights_and_event_type_are_not_keyword_matches():
    hunts = {hunt.id: hunt for hunt in HUNTS}
    limited = event(
        SourceImage=r"C:\powershell.exe", TargetImage=r"C:\lsass.exe", GrantedAccess="0x1000"
    )
    full = event(
        SourceImage=r"C:\powershell.exe", TargetImage=r"C:\lsass.exe", GrantedAccess="0x1fffff"
    )
    thread = event(EventID=8, SourceImage=r"C:\powershell.exe", TargetImage=r"C:\lsass.exe")
    assert hunts["lsass-query-only"].relevant(limited)
    assert not hunts["lsass-query-only"].relevant(full)
    assert hunts["lsass-full-access"].relevant(full)
    assert not hunts["powershell-to-lsass"].relevant(thread)
    assert hunts["lsass-remote-thread"].relevant(thread)


def test_equivalent_service_installation_providers_are_both_relevant():
    hunts = {hunt.id: hunt for hunt in HUNTS}
    security = event(Channel="Security", EventID=4697, ServiceName="PSEXESVC")
    system = event(Channel="System", EventID=7045, ServiceName="PSEXESVC")
    unrelated = event(Channel="System", EventID=6, ServiceName="PSEXESVC")
    assert hunts["psexesvc-installed"].relevant(security)
    assert hunts["psexesvc-installed"].relevant(system)
    assert not hunts["psexesvc-installed"].relevant(unrelated)


def test_ranking_metrics_use_the_correct_denominators():
    values = ranking_metrics(["n", "a", "b", "x", "c", "z"], {"a", "b", "c"})
    assert values["first_relevant_rank"] == 2
    assert values["hit_at_1"] == 0
    assert values["hit_at_5"] == 1
    assert values["precision_at_5"] == pytest.approx(3 / 5)
    assert values["recall_at_10"] == 1
    assert values["mrr_at_10"] == 0.5
    assert 0 < values["ndcg_at_10"] < 1
    assert ranking_metrics(["a"], {"a"})["precision_at_5"] == 0.2
    assert ranking_metrics(["n"] * 10 + ["a"], {"a"})["mrr_at_10"] == 0


def test_no_answer_cases_are_not_scored_as_successful_recall():
    result = ranking_metrics(["irrelevant"], set())
    assert "recall_at_10" not in result
    assert result["returned_count"] == 1
    assert ranking_metrics([], set())["returned_count"] == 0


def test_multiple_chunks_do_not_duplicate_an_event_in_scoring():
    vectors = np.asarray([[1, 0], [0, 1], [0.5, 0.5]], dtype=np.float32)
    scores = exact_event_scores(vectors, np.asarray([1, 0]), np.asarray([0, 0, 1]), 2)
    assert scores.tolist() == [1, 0.5]
    with pytest.raises(ValueError, match="at least one"):
        exact_event_scores(vectors[:1], np.asarray([1, 0]), np.asarray([0]), 2)


def test_scope_uses_utc_half_open_intervals_and_case_insensitive_device():
    value = event()
    assert in_scope(value, {"device": "alpha", "since": "2020-05-02T03:00:00Z"})
    assert not in_scope(value, {"device": "beta"})
    assert not in_scope(value, {"until": "2020-05-02T03:00:00Z"})


def test_lexical_baseline_has_no_semantic_or_label_injection():
    model = BM25(["powershell lsass handle", "chrome network request"])
    assert model.score("LSASS")[0] > model.score("LSASS")[1]
    assert model.score("not_a_known_term").tolist() == [0, 0]


def test_tied_scores_use_stable_ids_and_do_not_filter_main_cases(monkeypatch):
    a = event(SourceImage=r"C:\powershell.exe", TargetImage=r"C:\lsass.exe")
    b = event(SourceImage=r"C:\lsass.exe", TargetImage=r"C:\powershell.exe")
    case = Case("tie", "powershell-to-lsass", "query", "main", "literal", {})
    monkeypatch.setattr(evaluation, "cases", lambda: [case])
    manifest = {"labels": {"tie": {"positive_ids": [a.uid], "confuser_ids": [b.uid]}}}
    result = evaluate_scores("test", [np.array([0.5, 0.5])], [a, b], manifest)
    hits = result["results"][0]["top_10"]
    assert [hit["event_uid"] for hit in hits] == sorted([a.uid, b.uid])
    assert sum(hit["relevant"] for hit in hits) == 1
    assert sum(hit["confuser"] for hit in hits) == 1
