import argparse
import json
from pathlib import Path

import ijson
import requests
from qdrant_client.http.exceptions import ResponseHandlingException, UnexpectedResponse

from .config import ENCODERS, SECUREBERT, Settings
from .events import parse_timestamp
from .prepare import prepare
from .store import ingest, search, show_event, status


def positive_int(value: str) -> int:
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def timestamp_argument(value: str):
    try:
        return parse_timestamp(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline CPU vector search over security telemetry."
    )
    parser.add_argument(
        "--encoder",
        choices=list(ENCODERS),
        default=SECUREBERT.key,
        help="Local encoder; securebert (Cisco) is the default",
    )
    parser.add_argument("--collection", help="Override the encoder-specific collection")
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("prepare", help="ONLINE: download the pinned model and public logs")
    setup.add_argument("--data-dir", type=Path, default=Path("data"))
    setup.add_argument(
        "--model-only", action="store_true", help="Do not download the sample dataset"
    )
    load = commands.add_parser("ingest", help="OFFLINE: index a local log file")
    load.add_argument("path", type=Path)
    load.add_argument("--format", choices=["jsonl", "json-array", "defender"], default="jsonl")
    selection = load.add_mutually_exclusive_group()
    selection.add_argument("--limit", type=positive_int)
    selection.add_argument(
        "--sample-per-group",
        type=positive_int,
        help="Sample up to N records per device/event type; scans the whole file",
    )
    load.add_argument("--batch-size", type=positive_int, default=128)
    query = commands.add_parser("search", help="OFFLINE: return matching original events")
    query.add_argument("query")
    query.add_argument("--top-k", type=positive_int, default=5)
    query.add_argument("--device", help="Case-insensitive exact hostname")
    query.add_argument("--event-id")
    query.add_argument("--event-type")
    query.add_argument("--channel")
    query.add_argument(
        "--since", type=timestamp_argument, help="Inclusive ISO timestamp with timezone"
    )
    query.add_argument(
        "--until", type=timestamp_argument, help="Exclusive ISO timestamp with timezone"
    )
    query.add_argument("--raw", action="store_true", help="Include complete original JSON events")
    event = commands.add_parser("show", help="OFFLINE: retrieve an original event by event_uid")
    event.add_argument("event_uid")
    commands.add_parser("status", help="OFFLINE: inspect the persisted collection")
    evaluation = commands.add_parser(
        "evaluate", help="OFFLINE: compare Cisco, MiniLM and BM25 on labeled real-event queries"
    )
    evaluation.add_argument("--source", type=Path, default=Path("data/apt29-day1.jsonl"))
    evaluation.add_argument(
        "--output-dir", type=Path, default=Path(".blurag/evaluation/relevance-v2")
    )
    evaluation.add_argument("--prepare-only", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        settings = Settings.from_env(args.collection, encoder=args.encoder)
        if args.command == "prepare":
            result = prepare(settings, args.data_dir, model_only=args.model_only)
        elif args.command == "ingest":
            result = ingest(
                settings,
                args.path,
                input_format=args.format,
                limit=args.limit,
                batch_size=args.batch_size,
                sample_per_group=args.sample_per_group,
            )
        elif args.command == "search":
            result = search(
                settings,
                args.query,
                top_k=args.top_k,
                include_raw=args.raw,
                device=args.device,
                event_id=args.event_id,
                event_type=args.event_type,
                channel=args.channel,
                since=args.since,
                until=args.until,
            )
        elif args.command == "show":
            result = show_event(settings, args.event_uid)
        elif args.command == "evaluate":
            from .evaluation import run_benchmark

            if args.collection is not None:
                raise ValueError("Evaluation uses its own frozen, encoder-specific collections.")
            result = run_benchmark(settings, args.source, args.output_dir, args.prepare_only)
        else:
            result = status(settings)
        print(json.dumps(result, indent=2, allow_nan=False))
    except (
        ValueError,
        OSError,
        requests.RequestException,
        ijson.JSONError,
        UnexpectedResponse,
        ResponseHandlingException,
    ) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
