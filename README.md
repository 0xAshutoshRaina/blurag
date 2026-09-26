# BluRag

Search Windows security logs with local embedding models and Qdrant.
Download the software, model and sample logs once; ingestion and search then
run offline on CPU. No LLM or agent.

We compared Cisco SecureBERT, MiniLM and BM25 on 120 queries. **MiniLM performed
best in this experiment; the security-specific model did not.**
[Results and method](EVALUATION.md) · [All queries](research/relevance-v2/cases.md)

## Run it

Requires Docker with Compose. Tested on an ARM64 Mac with 24 GiB RAM.

```sh
git clone https://github.com/0xAshutoshRaina/blurag.git
cd blurag
docker compose build cli
docker compose pull qdrant
./blurag prepare
```

Setup downloads about 600 MB of Cisco model files and a 14 MB log archive
(385 MB unpacked), plus the container images.

Index a small sample, then search it:

```sh
./blurag ingest data/apt29-day1.jsonl --sample-per-group 10

./blurag search "PowerShell connecting to destination port 443" \
  --device SCRANTON.dmevals.local \
  --event-type network_connection \
  --top-k 5
```

The sample selects up to ten events per host/event-type pair across the full
file. It contains 758 events, not the whole dataset, and can miss specific
behaviors. Omit `--sample-per-group` to index everything; Cisco can take hours
on CPU. Reingesting unchanged records does not add duplicates.

## Query options

Device, event type, event ID and time filters are optional. Omit `--event-type`
to search across event types. Time bounds use `--since` (inclusive) and
`--until` (exclusive), with an explicit timezone such as `2020-05-02T03:00:00Z`.

Results include a score and a reference to the original event. Use `--raw` to
include its full JSON, `./blurag show EVENT_UID` to retrieve it, and
`./blurag status` to inspect the collection. `./blurag search --help` lists
all options.

Cisco is the default encoder. To use MiniLM instead:

```sh
./blurag --encoder minilm prepare --model-only
./blurag --encoder minilm ingest data/apt29-day1.jsonl
./blurag --encoder minilm search "PowerShell accessing LSASS"
```

Each encoder uses a separate collection. Put `--encoder` and `--collection`
before the subcommand.

## Use your own logs

Place exports in `data/`. The parser accepts flat Windows/Sysmon records and
common Defender fields:

```sh
./blurag --collection my_case ingest data/events.jsonl
./blurag --collection my_case search "process creating a network connection"
```

JSONL is the default. Use `--format json-array` for an array or
`--format defender` for a `{"Results": [...]}` export. Records need a device and
a timestamp: `UtcTime`, `Timestamp`, or `@timestamp`. Only `UtcTime` may omit the
timezone. Malformed records stop ingestion; completed batches remain stored.

## Limits

Similarity is not a threat verdict. Search can confuse process roles and return
unrelated neighbors when the requested behavior is absent. It does not correlate
events into an attack chain. See the [measured failures](EVALUATION.md).

Models and databases live in `.blurag/`; logs live in `data/`. Neither directory
is published. Only `prepare` has internet access; the CLI and Qdrant use an
internal-only Docker network with no published ports. This is not disk encryption
or a claim that the host is air-gapped.

Stop Qdrant with `docker compose stop qdrant`. The next command starts it again.

## Tests and research

```sh
docker compose run --rm --no-deps --entrypoint sh cli \
  -c 'ruff check src tests && pytest -q -m "not integration"'
```

[Research files, reproduction and sources](research/README.md).
Code and documentation: [Apache-2.0](LICENSE). Data and models retain their
own licenses; see [NOTICE](NOTICE).
