# BluRag: offline telemetry vector search

A CPU-only P1 proof of concept: turn local Windows security logs into a persisted
vector index, then search that index in natural language. No generative LLM,
agent, cloud embedding API, live EDR connection, or threat verdict is involved.

**The default encoder is Cisco's SecureBERT 2.0 Bi-Encoder.** Its public
weights are Apache-2.0 licensed and run locally without a subscription,
API key, or per-query/model-service charge. Inference uses local CPU, memory,
and electricity. MiniLM remains available in a separate model/index profile.

**Research finding:** on our 96-query main challenge set, a relevant event
appeared in the top five for **79.2% with MiniLM, 59.4% with BM25, and 27.1%
with Cisco**. This is a comparison of the current telemetry representations and
chunking setups, not a universal model ranking. See [the evaluation](EVALUATION.md)
and [all 120 published queries](research/relevance-v2/cases.md).

The repository includes code and research results, **not logs, model weights,
or prebuilt databases**. The measurements below describe completed local runs;
a fresh clone must prepare its own models and data.

```text
Connected preparation:
  Public log archive + pinned model weights + Python/container dependencies

Offline ingestion:
  Local JSON logs -> deterministic field normalization -> token-bounded chunks
                 -> Cisco SecureBERT CPU embeddings -> local Qdrant server

Offline search:
  Search text -> same local embedding model -> filtered vector retrieval
              -> ranked events, source references, and original JSON
```

## Run it

Docker with the Compose plugin is the only host runtime prerequisite. The
application uses Python 3.12 inside a container; the host Python is not changed.
The recorded runs used an ARM64 Mac with 24 GiB RAM.

Clone and prepare while connected:

```sh
git clone https://github.com/0xAshutoshRaina/blurag.git
cd blurag
docker compose build cli
docker compose pull qdrant
./blurag prepare
```

Preparation downloads approximately 14 MB of compressed logs (385 MB unpacked)
and roughly 600 MB of Cisco model/tokenizer files, in addition to the container
images and dependencies. For an existing setup with the sample logs already
downloaded, `./blurag prepare --model-only` prepares only the selected encoder.
It pins the dataset and model revisions, verifies the archive checksum, saves
file checksums, and retains the dataset's license and upstream description.
Only JSON telemetry is extracted; no emulation tools or executables are run.

From here, ingestion and queries require no internet:

```sh
# A bounded pilot spanning the entire source file, all hosts and event types.
./blurag ingest data/apt29-day1.jsonl --sample-per-group 10

./blurag search "outbound network connection" --event-type network_connection
./blurag search "registry value modification" --event-type registry_value_set
./blurag status

# Explicitly grow to the full dataset. CPU inference can take hours.
# Previously indexed sample points are skipped.
./blurag ingest data/apt29-day1.jsonl
```

The wrapper starts the local database when needed and waits for its readiness
probe. All command results are JSON on stdout; ingestion progress and operational
messages go to stderr. `status` distinguishes unique original events from vector
chunks. Its `indexed_vectors` field counts HNSW entries, not stored embeddings;
a small collection may report zero while remaining searchable by exact scan.

## Encoders and separate indexes

| Encoder flag | Model | Runtime | Dimensions | Default collection |
|---|---|---|---|---|
| `--encoder securebert` (default) | [Cisco SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder) | Sentence Transformers + PyTorch CPU | 768 | `blurag_securebert` |
| `--encoder minilm` | [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) | FastEmbed + ONNX CPU | 384 | `blurag_events` |

Cisco's checkpoint is a cybersecurity retrieval bi-encoder, not the base masked
language model or a generative model. The pinned revision is
`b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0`. It has approximately 149 million
parameters and uses the publisher's mean-pooling configuration. Its Sentence
Transformer input window is 1,024 tokens, even though the backbone configuration
supports longer sequences.

Cisco inference uses float32, normalized output vectors, CPU SDPA attention, and
eight-text inference batches. The CLI's `--batch-size` controls database batches,
not this smaller inference batch. CUDA, Flash Attention, remote model code, and
automatic downloads are not required.

To prepare, populate, and query the MiniLM collection separately:

```sh
./blurag --encoder minilm prepare --model-only
./blurag --encoder minilm ingest data/apt29-day1.jsonl
./blurag --encoder minilm status
./blurag --encoder minilm search "PowerShell process creation" --event-type process_creation
```

Encoder selection applies to preparation, ingestion, querying, and status.
Both encoder flags and `--collection` go before the subcommand. Existing vector
spaces are never mixed or silently rebuilt; choosing the wrong encoder for a
collection fails with a configuration error.

### Filter and inspect evidence

```sh
./blurag search "outbound network connection" \
  --device SCRANTON.dmevals.local \
  --event-type network_connection \
  --since 2020-05-02T02:55:00Z \
  --until 2020-05-02T03:29:00Z \
  --top-k 3 \
  --raw

./blurag search "outbound network connection" --event-id 3 --top-k 5
./blurag show EVENT_UID_FROM_A_SEARCH_RESULT
```

Hostnames are exact matches, case-insensitive. Event IDs, event types, and
`--channel` are exact matches. Times require a timezone; `--since` is inclusive
and `--until` is exclusive. These filters constrain Qdrant retrieval itself;
they are not inferred by an LLM or applied only after retrieving global top-k.

Results are grouped by original event, so a long event cannot occupy every
result slot merely because it produced several chunks. `text` is the matching
chunk, not necessarily the whole record. Use `--raw` or `show` to inspect the
complete original JSON, including exact command lines, IDs, paths, and hashes.
Cosine similarity is not a probability that an event is malicious.

## Sample data and provenance

The sample is **OTRF Security-Datasets, APT29 emulation, day 1**, created by
Roberto Rodriguez. It contains genuine Windows telemetry recorded during a lab
exercise, including background activity. It is not production customer data,
and not every event is malicious.

- Source: [OTRF APT29 dataset](https://github.com/OTRF/Security-Datasets/tree/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/compound/apt29).
- Pinned revision: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`.
- Archive SHA-256: `98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5`.
- **196,081 records**, **385,334,029 uncompressed bytes**, four hosts.
- Hosts: `SCRANTON`, `NASHUA`, `NEWYORK`, and `UTICA`, under `dmevals.local`.
- Recorded timestamps cover approximately **2020-05-02 02:55-03:28 UTC**.
- Providers include Sysmon, Windows Security, PowerShell, WMI, and System.
- License: the pinned repository's `LICENSE` is MIT, copied to
  `data/OTRF-LICENSE.txt`. The upstream README contains a stale GPL heading;
  use the actual license file at the pinned revision.

The upstream dataset descriptions disagree on some event counts. The numbers
above come from reading the exact pinned archive, not from those descriptions.
`data/dataset-manifest.json` records the extracted file's checksum and count.

## Cisco pilot and original baseline

The recommended Cisco run starts with a **type-stratified pilot**, not all 196,081
events. `--sample-per-group 10` selects up to ten events per device/event-type
pair using the lowest content hashes across the complete file. This is a
reproducible way to include rare event types and all hosts without indexing the
entire source. It is not proportional sampling or a production-frequency
benchmark. Original file and record-number references are retained.

The recorded local pilot contained **758 original events and 793 vector chunks**,
covering four hosts and all 26 normalized event types. Ingestion took
**507.649 seconds (about 8.5 minutes)**, including 489.472 seconds in embedding
batches. All selected original records survived a database restart unchanged;
rerunning the same selection wrote zero new points and took about 22 seconds.

A preliminary CPU probe of 76 events spanning all 26 normalized event types
produced 77 Cisco chunks in 43.8 seconds of embedding time. This larger encoder
is substantially slower than MiniLM on the current CPU runtime, so a full Cisco
reindex is an explicit command rather than an automatic migration.

This pilot is not a complete hunting corpus: the sampled process-creation
records contain no PowerShell executions, and the sampled process-access records
contain no LSASS targets. Searching for those behaviors still returns the nearest
available vectors, not proof of a match. Use the network/registry examples above
for the pilot, or explicitly index more source records before evaluating those
other hunts. These coverage gaps must not be mistaken for an encoder-quality
comparison.

Use `./blurag status` for the actual current Cisco event/chunk counts and
`.blurag/reports/securebert-last-ingest.json` for the latest completed ingestion.
After a full MiniLM ingestion, that separate index is searchable with
`--encoder minilm`.

The following measurements describe the **original MiniLM run**, not Cisco:

| Measurement | Observation |
|---|---|
| Hardware | ARM64 Mac, 24 GiB host RAM, 10 logical CPUs |
| Docker resources | About 7.65 GiB RAM available; embedding uses 4 CPU threads |
| Original events stored | 196,081 |
| Vector chunks stored | 227,593 |
| Full ingestion | 2,896.963 seconds, approximately 48.3 minutes |
| Time inside embedding batches | 2,708.230 seconds |
| Database directory after ingestion | Approximately 1.0 GiB |
| Prepared model directory | Approximately 98 MiB |
| Dataset files, including archive | Approximately 381 MiB |
| Five example searches returning results | 14-708 ms in Qdrant; 0.56-1.41 s in the Python search call |

These are single-run observations, not a controlled performance benchmark.
Some inspection and test activity ran concurrently. The search timings exclude
Docker startup and initial Python imports; they include loading the model anew
for each search call. They are not percentile estimates or guarantees.

Recreating the database container preserved all 196,081 events and 227,593
chunks. Reingesting the first 10,000 records wrote zero new points and took about
12 seconds, without recomputing their embeddings. Example results were compared
with the source JSON. Both the real-model integration run and the example
queries completed with external socket connections forbidden; a direct internet
connection from the ordinary CLI container failed as expected.

These historical local artifacts are not included in Git. New ingestion reports
are encoder-specific under `.blurag/reports/`. The shareable model-comparison
results and recorded runtime versions are under [research/](research/README.md).

## Bring your own exported logs

Put files under `data/` so the container can access them:

```sh
./blurag --collection my_investigation ingest data/my-events.jsonl
./blurag --collection my_investigation ingest data/event-array.json --format json-array
./blurag --collection my_investigation ingest data/hunting-export.json --format defender
./blurag --collection my_investigation search "process creating a network connection"
```

Supported inputs are newline-delimited JSON objects (the default), a top-level
JSON array, or a Defender-style `{"Results": [...]}` wrapper. All formats are
read incrementally. ZIP/EVTX parsing, live KQL extraction, arbitrary nested event
schemas, and automatic schema discovery are outside P1.

The normalizer recognizes flat Sysmon/Windows event fields and common Defender
fields. A device name/ID and a usable timestamp are required. Timestamp
precedence is `UtcTime`, `Timestamp`, then `@timestamp`; the chosen field is
recorded in each payload. Only Sysmon's explicitly UTC `UtcTime` accepts a
timestamp without an offset. Ambiguous local `EventTime` is not silently
interpreted as UTC. A collector's `@timestamp` can be a receipt time rather than
the event's occurrence time.

Windows provider and event ID determine descriptive event types. Unknown event
IDs retain a generic provider label and their available evidence. No ATT&CK or
maliciousness labels are fabricated. Normalized embedding text emphasizes
commands, processes, files, registry activity, and connections; host and time
remain structured metadata. The complete original record is always stored.

Malformed records stop ingestion with an error. Earlier completed batches
remain in the database. Correct the input and rerun: unchanged records have
stable content-derived IDs and are not embedded or inserted again. Identical
JSON records collapse to one event. Changed records become new events; deleting
records from an input file does not remove previously indexed evidence.
The existing `--limit N` option still selects the first N records; it cannot be
combined with `--sample-per-group`. A later full ingestion extends a sampled
collection without duplicating already indexed events.

## Storage and offline boundary

| Location | Contents |
|---|---|
| `data/apt29-day1.jsonl` | Extracted original telemetry |
| `data/downloads/` | Pinned source archive |
| `data/dataset-manifest.json` | Dataset provenance and checksums |
| `.blurag/securebert-model/` | Cisco weights, tokenizer, pooling/configuration, checksum manifest |
| `.blurag/model/` | Preserved MiniLM model and checksum manifest |
| `.blurag/qdrant/` | Persistent database files |
| `.blurag/reports/securebert-last-ingest.json` | Most recent Cisco ingestion metrics |
| `.blurag/reports/minilm-last-ingest.json` | Most recent MiniLM ingestion metrics, if rerun |
| `research/` | Published query matrix, metrics and source references; no raw telemetry |

Qdrant is a real local server with HNSW support, not the Python client's
small-data in-process mode. It uses cosine distance over encoder-specific
float32 vectors. Neither model nor stored vectors are INT8-quantized.
Model-weight quantization and vector-storage quantization would be
separate later experiments.

Cisco embedding text uses 960-token chunks with 64-token overlap; MiniLM retains
224-token chunks with 32-token overlap. Each encoder uses its own tokenizer and
rejects over-window inputs rather than silently dropping command-line tails.
The pipeline/model fingerprint
is part of the vector schema; incompatible collections are rejected instead of
silently mixing embedding spaces. Changes to normalization or chunking require
bumping the pipeline version and reindexing into a new collection.

The database and ordinary CLI containers attach **only** to Compose's
`internal: true` network. No database port is published to the host or LAN.
Only the separate `prepare` service gets a network with internet access.
Model loading uses a specific local directory and `local_files_only=True`;
missing or modified model files cause an error, not a download.
Qdrant and Hugging Face telemetry are disabled.

This is application-level network isolation on an otherwise connected host,
not a claim that the physical machine is air-gapped. To move the PoC to an
actually disconnected machine, transfer the source, prepared data/model files,
and saved container images. Stop Qdrant before copying its live storage, or use
a Qdrant snapshot. The offline machine must already have Docker installed.

```sh
# Stop the database without deleting its contents.
docker compose stop qdrant
```

The next wrapper command starts it again. Local storage is not encryption or a
multi-user authorization system. Protect the directory and backups accordingly.

## Development checks

For the concrete correctness-test inventory and the separate **120-query
retrieval-quality comparison**, see [EVALUATION.md](EVALUATION.md). After preparing
both encoders, run the following to compare Cisco, MiniLM and BM25 on the same
frozen set of real events:

```sh
./blurag prepare
./blurag --encoder minilm prepare --model-only
./blurag evaluate
```

The evaluation uses separate benchmark collections with field-grounded positives
and misleading near-matches. You do not need to populate either main collection
first. [Published results](research/README.md) are readable without downloading
anything; local runs generate the detailed raw-evidence reports.

The image includes the small development dependencies. Once built, unit checks
do not need the internet:

```sh
docker compose run --rm --no-deps --entrypoint sh cli \
  -c 'ruff check src tests && pytest -q -m "not integration"'
```

After preparation and database startup, the integration check uses the actual
CPU models and server in isolated temporary collections:

```sh
docker compose up -d qdrant
docker compose run --rm --no-deps -e BLURAG_RUN_INTEGRATION=1 \
  --entrypoint pytest cli -q -m integration
```

It checks both encoders' real embeddings, persisted retrieval, idempotent
ingestion, long-event grouping, device/time filters, raw evidence, and absence
of external socket connections. It removes only its own temporary collections
and does not replace the main ingestion reports. Prepare MiniLM separately with
`./blurag --encoder minilm prepare --model-only` on a fresh installation before
running both live-encoder checks.

## What this experiment does not establish

This is filtered semantic retrieval, not a hybrid lexical engine, exhaustive
threat detector, timeline correlator, or replacement for structured hunting
queries. Exact indicator searches and behavior rules remain valuable future
comparisons. Similarity search can miss relevant evidence and return benign
events; no matching result does not prove absence of a threat.

An early MiniLM query about processes accessing LSASS also returned records where
LSASS was the *source* rather than the *target*. Switching to a security-trained
encoder does not establish that this problem is solved. Cisco's documented
retrieval training emphasizes security documents and Q&A rather than this
particular Sysmon corpus. Inspect the original fields and measure retrieval
quality before interpreting an operation's direction or a threat's presence.
Neither encoder reconstructs missing cross-event process relationships.

Current measurements should be treated as observations on this dataset and
machine, not capacity or latency guarantees. The JSON output separates model
loading/query embedding from database search time. Its `total_seconds` measures
the Python search call, excluding container startup and initial imports. Large records
produce multiple vectors and repeat their raw payload per chunk, favoring
simplicity and inspectable evidence over storage efficiency at this stage.
P2, including LLM/agent synthesis, is intentionally absent.

## License and attribution

Original project code and documentation are licensed under
[Apache-2.0](LICENSE). Dataset, model and dependency licenses remain separate;
see [NOTICE](NOTICE) and [research provenance](research/README.md). This is
independent research, not an endorsed product or a validated threat detector.
