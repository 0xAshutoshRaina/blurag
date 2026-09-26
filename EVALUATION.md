# What BluRag tests, and what it does not

## Measured outcome

**Cisco is not an improvement on this challenge set with the current text
representation and chunking.** Of the 96 main queries, it found a relevant event
in the first five for **26**, compared with **76** for MiniLM and **57** for BM25.
These results do not establish that Cisco is generally worse for cybersecurity
documents or other input representations. Neither encoder is a reliable
standalone detector.

| Retriever | Relevant at rank 1 | At least one relevant in top 5 | In top 10 | MRR@10 |
|---|---:|---:|---:|---:|
| BM25 keywords | 39.6% | 59.4% | 69.8% | 0.478 |
| MiniLM | 46.9% | 79.2% | 85.4% | 0.593 |
| Cisco SecureBERT | 12.5% | 27.1% | 33.3% | 0.186 |

Some concrete examples, showing the **first relevant rank** among 649 candidates:

| Query | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|
| PowerShell accessing LSASS | 9 | 1 | 85 |
| PowerShell creating a remote thread in LSASS | 1 | 1 | 169 |
| PowerShell connecting to 10.0.1.6 on destination port 5985 | 1 | 1 | 30 |
| PowerShell extracting code bytes from image pixels | 60 | 1 | 3 |
| Installation of PSEXESVC | 4 | 1 | 1 |
| Secure-delete utility launches against ZIP archives | 8 | 3 | 252 |
| PowerShell contacting the LDAP listener on the domain controller | 235 | 90 | 77 |

The LDAP paraphrase is a useful failure for **all three**, not evidence that
MiniLM solved the task. Changing wording also changes rankings significantly.
All six no-answer controls still return neighbors with nonzero scores; no
retriever implements a validated abstention decision.

Open the [120-query matrix](research/relevance-v2/cases.md) for exact wording and
individual ranks, and the [machine-readable results](research/relevance-v2/results.json)
for every case's metrics and top-ten source references. Raw evidence and
command-line snippets are deliberately not published. Running the evaluator
locally creates `.blurag/evaluation/relevance-v2/report.md`, with expected source
evidence and five actual returned events per model per query.

## Two different kinds of tests

The original **45 parameterized tests** checked software behavior.
They did not establish that an embedding model retrieves the right security
evidence. The new relevance benchmark is separate from pytest: poor model
rankings are reported, not hidden behind passing software tests.

| Existing area | Cases exercised |
|---|---|
| CLI | Cisco default, explicit MiniLM selection, option parsing, sampling/limit exclusivity, model-only preparation |
| Input formats | Streaming JSONL, JSON arrays, Defender `Results`, malformed JSON with physical line numbers, rejection of non-object rows |
| Normalization | Original JSON preservation, stable content IDs, UTC timestamp precedence, timezone validation, device names versus disk names, provider-specific event semantics, message-only evidence |
| Invalid records | Missing device, missing timestamp, ambiguous naive timestamp, non-scalar fields |
| Tokenization | Long-record tail preservation, bounded overlapping chunks, no duplicate short chunks, empty/oversized input errors |
| Models | Checksums for every file, missing model rejection without downloading, correct dimensions and normalized real vectors, CPU inference and pooling configuration |
| Index isolation | Separate encoder profiles, rejection of another model's collection, no silent replacement of incompatible vectors |
| Ingestion | Repeated runs add no duplicates; malformed later records preserve committed batches; deterministic sampling; full ingestion extends a sample |
| Retrieval | Unique-event grouping, device/event/time filters, empty result sets for nonexistent devices, original evidence lookup |
| Offline integration | Both actual local encoders and Qdrant, explicit rejection of external socket connections, no changes to the main collection or its reports |

To list every concrete pytest node, including both encoders and invalid-input
variants:

```sh
docker compose run --rm --no-deps --entrypoint pytest cli --collect-only -q
```

## The relevance benchmark

There are **120 exact queries**, including **96 main queries across 32 behavior
families**, plus 24 diagnostic queries. Each main behavior has three formulations:
a literal query, a paraphrase, and an investigative formulation.

| Category | Concrete distinctions being tested |
|---|---|
| Command semantics | Screensaver launching cmd; hidden PowerShell with execution-policy bypass; extracting code from image pixels; SDelete targeting ZIP archives; PsExec launching Python remotely; rundll32 WebDAV function invocation |
| Parent and child | PowerShell itself starting versus its conhost/csc children; parent command-line text must not be mistaken for the child's own command |
| Access direction | PowerShell accessing LSASS versus LSASS accessing PowerShell |
| Exact rights | `0x1000` query-limited access versus `0x1fffff` access; neither alone proves a dump |
| Event type | LSASS process-handle access versus remote-thread creation; service installation versus execution |
| Network semantics | PowerShell to destination ports 443, 5985 and 389; PsExec to RPC port 135; exact destination IPs |
| DNS versus traffic | PowerShell resolving the Gallery domain versus establishing a network connection |
| Registry artifacts | Folder shell-open default command, empty DelegateExecute, service ImagePath versus other values, Defender's legitimate Run entry |
| File operations | Creating an archive versus commands deleting it; writing monkey.png versus reading it; DLL file creation versus image load |
| Authentication | Explicit credentials from PSEXESVC versus successful logon; network logon type 3 versus interactive type 2 |
| Mixed evidence | Retrieve both PsExec launch/service-install records, and both PowerShell-to-LSASS access/thread records; no causal-chain claim |
| No-answer controls | Absent certutil download, shadow-copy deletion, mshta URL execution, failed pbeesly logons, a nonexistent destination IP, and a nonexistent service |
| Scope controls | Host/time written only in the query versus actual metadata filters; empty device and future-time windows |
| Query robustness | Short forms, aliases and misspellings such as `powershel accessing lsass` |

### Evidence and fairness

The selected corpus contains **649 real events from the original 196,081-event
OTRF file**, with known positives for every positive behavior. The six no-answer
rules were checked against the entire source file. Selection uses content hashes,
not a model's preferred results: up to eight positives and eight confusers per
behavior, plus six background events per device/type and scoped-case positives.

This is deliberately a challenge set, not a random production workload. It
overrepresents useful evidence and rare event types. The queries were authored
after inspecting the dataset, so this is **not independent held-out evidence**
and cannot establish production recall or general cybersecurity understanding.

All three retrievers search the **same events**:

- MiniLM, with its existing 224-token chunks.
- Cisco SecureBERT 2.0 Bi-Encoder, with its existing 960-token chunks.
- A transparent BM25 keyword baseline over the same normalized event text.

Main cases have **no event-type, device, or time filter**. The separate scope
diagnostics do not contribute to the main quality average. Dense scoring uses
exhaustive cosine similarity rather than approximate nearest-neighbor retrieval,
takes the best chunk score per event, and breaks ties by event ID.

Ground truth comes from inspectable predicates on the original log fields, not
from embedding similarity, invented maliciousness labels, or an LLM judge.
Every selected event is evaluated against each rule; labels are not limited to
the originally selected seed examples. Predicates, queries, source references
and checksums are frozen together in the benchmark manifest.

The initial v1 run missed a provider-equivalence rule: System event 7045 is a
valid service-installation record as well as Security event 4697. An evidence
audit caught this; v2 includes both for all models without changing model inputs.
The initial run remains preserved in the original local workspace. The public
artifacts and table above use v2.

### Run and inspect

```sh
# On a fresh clone, first build and prepare both encoders while connected.
docker compose build cli
docker compose pull qdrant
./blurag prepare
./blurag --encoder minilm prepare --model-only

# Construct and inspect the frozen case/corpus manifest without model inference.
./blurag evaluate --prepare-only

# Run or resume the comparison. Uses the downloaded local models; no internet.
./blurag evaluate
```

The run uses separate `blurag_eval_*` collections; it does not extend, delete, or
relabel the main Cisco pilot or MiniLM corpus. A changed case definition requires
a new output directory, for example `--output-dir .blurag/evaluation/relevance-v3`.
Rerunning an unchanged completed evaluation reads its saved results.

The generated local `report.md` includes every query, every first-relevant rank,
source-grounded expected examples, and the first five returned events per model.
Adjacent per-model JSON files contain the first ten hits. Its local `manifest.json`
contains the raw-field rules, labels and selection parameters.

The [public provenance](research/relevance-v2/provenance.json) records the pinned
source checksums and selected original source rows. The
[case definitions](src/blurag/evaluation_cases.py) and
[evaluator](src/blurag/evaluation.py) provide the executable ground-truth rules.
See [research/README.md](research/README.md) for reproduction and the deliberate
omission of log bodies, credentials, vectors and model weights from Git.

The evaluator itself has additional unit tests for role reversal, exact access
masks, metric denominators, empty-answer handling, chunk grouping, metadata
boundaries, BM25 behavior, and deterministic tied-score ordering. These tests
verify the measuring code; they do not assert that either embedding model is good.
