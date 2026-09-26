import pytest

from blurag.cli import build_parser


def test_cisco_is_the_default_and_minilm_is_explicit():
    parser = build_parser()
    assert parser.parse_args(["status"]).encoder == "securebert"
    baseline = parser.parse_args(["--encoder", "minilm", "search", "prepare"])
    assert baseline.encoder == "minilm"
    assert baseline.command == "search"
    assert baseline.query == "prepare"


def test_sampling_and_prefixes_are_explicit():
    parser = build_parser()
    args = parser.parse_args(["ingest", "data/events.jsonl", "--sample-per-group", "10"])
    assert args.sample_per_group == 10
    assert args.limit is None
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["ingest", "data/events.jsonl", "--sample-per-group", "10", "--limit", "100"]
        )


def test_model_preparation_does_not_require_dataset_download():
    args = build_parser().parse_args(["--encoder", "minilm", "prepare", "--model-only"])
    assert args.model_only
    assert args.command == "prepare"
