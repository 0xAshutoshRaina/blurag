# Retrieval results

We asked whether a security-specific encoder would retrieve Windows telemetry
better than a small general-purpose model or keyword search.
**In this experiment, MiniLM outperformed Cisco SecureBERT.**

## Results

These scores cover the 96 main queries. Hit@k means at least one relevant event
appeared in the first k results. MRR@10 rewards earlier matches and counts
anything beyond rank ten as zero.

| Retriever | Hit@1 | Hit@5 | Hit@10 | MRR@10 |
|---|---:|---:|---:|---:|
| BM25 | 39.6% | 59.4% | 69.8% | 0.478 |
| MiniLM | 46.9% | 79.2% | 85.4% | 0.593 |
| Cisco SecureBERT | 12.5% | 27.1% | 33.3% | 0.186 |

Examples below show the first relevant rank, not a confidence score:

| Query, shortened | BM25 | MiniLM | Cisco |
|---|---:|---:|---:|
| PowerShell accessing LSASS | 9 | 1 | 85 |
| PowerShell creating a remote thread in LSASS | 1 | 1 | 169 |
| PowerShell connecting to 10.0.1.6:5985 | 1 | 1 | 30 |
| PowerShell extracting code from image pixels | 60 | 1 | 3 |
| Installation of PSEXESVC | 4 | 1 | 1 |
| PowerShell contacting the domain controller's LDAP listener | 235 | 90 | 77 |

The LDAP paraphrase failed for all three. All six absent-behavior queries
returned neighbors anyway. Neither encoder is reliable enough here to treat
search results as proof that a threat is present or absent.

[Every query and rank](research/relevance-v2/cases.md) ·
[Full metrics and top-ten source references](research/relevance-v2/results.json)

Separate ingestion runs on the 24 GiB ARM64 Mac took 48.3 minutes for all
196,081 events with MiniLM and 8.5 minutes for the 758-event Cisco pilot.
These used different corpora and are not a controlled speed comparison.

## Method

We selected **649 real events** from OTRF's 196,081-event APT29 day-one dataset.
The set includes known matches, similar but incorrect events, and background
activity from all four hosts. Selection uses content hashes: up to eight matches
and eight near-matches per behavior, six background events per host/type, and
additional records for the scope tests.

| Queries | Purpose |
|---:|---|
| 96 | 32 behaviors, each phrased literally, as a paraphrase, and as an investigative question |
| 6 | Retrieve multiple relevant event types together |
| 6 | Search for behavior verified absent from the full source |
| 6 | Compare host/time in query text with explicit filters, including empty scopes |
| 6 | Short queries and typos |

The cases distinguish parent from child commands, LSASS access direction,
access rights, thread creation, DNS from connections, registry changes, file
creation from deletion, and service installation from execution.

All retrievers search the same events. Main queries have **no host, time or
event-type filter**. Relevance is defined by
[rules over original log fields](src/blurag/evaluation_cases.py), applied to every
candidate, not by model scores or an LLM judge.

Dense retrieval uses exact cosine scoring, the best chunk score per event, and
event ID to break ties. MiniLM uses 224-token chunks; Cisco uses 960-token
chunks. BM25 searches the same normalized event text. This compares the current
retrieval setups, not just model weights in isolation.

## Caveats

The queries were written after inspecting this dataset. This is a small,
deliberately selected challenge set, not an independent holdout or an estimate
of production recall. The three phrasings of each behavior are related tests,
not independent trials.

Revision 2 corrects one labeling gap: both Security event 4697 and System event
7045 count as service installation. The correction applies to all models.
No embeddings or query text were changed.

Unit and integration tests cover parsing, filters, persistence, offline
inference and the scoring code. Passing those tests says nothing about retrieval
quality.

For commands, source attribution, runtime versions and downloadable results,
see [research/README.md](research/README.md).
