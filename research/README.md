# Published research artifacts

The [120-query matrix](relevance-v2/cases.md) and [machine-readable results](relevance-v2/results.json)
publish the measured comparison of BM25, MiniLM, and Cisco SecureBERT 2.0.
Read [EVALUATION.md](../EVALUATION.md) for the research question, outcomes, exact
metric definitions, correctness-test inventory, and limitations.

The comparison covers 649 selected real events from a 196,081-event public
lab-emulation dataset. The main 96 queries have no metadata or event-type
prefilters. Six mixed-evidence, six no-answer, six scope, and six short-query
diagnostics are reported separately. Neither these results nor the
security-specific model name establish reliable automated threat detection.

## What is published

| File | Contents |
|---|---|
| `relevance-v2/cases.md` | Every exact query and first-relevant rank for each retriever |
| `relevance-v2/results.json` | Per-case metrics, positive/confuser source rows, and top-ten ranks, scores and source references |
| `relevance-v2/provenance.json` | Source/corpus/definition checksums and selected original row numbers |

No raw event bodies, command-line snippets, original credentials (including
lab credentials), embeddings, local model weights, database files, or personal
filesystem paths are published. The `event_uid` values are content hashes of
records from the pinned public dataset; `source_record` is the original
one-based JSONL line number, not the subset-file line number.

Raw evidence remains available from the attributed upstream dataset. The
local evaluator regenerates a detailed evidence report after downloading it;
the public result tables do not require redistributing the logs.

## Reproduce from a fresh clone

Docker and the Compose plugin are required. Both models and software dependencies
must be prepared while connected:

```sh
docker compose build cli
docker compose pull qdrant
./blurag prepare
./blurag --encoder minilm prepare --model-only
```

The following command runs on the internal-only network and creates separate
benchmark collections without populating the production/pilot collections:

```sh
./blurag evaluate
```

Local outputs appear under `.blurag/evaluation/relevance-v2/`. They include the
full evidence report, original subset, source labels and per-model results.
They are ignored by Git. The default Cisco pilot and full MiniLM index described
in the documentation are historical runs, not databases included in a clone.

The existing manifest freezes the cases and subset; rerunning a completed
evaluation reads cached results. To force a fresh measurement, use a new output
directory, for example:

```sh
./blurag evaluate --output-dir .blurag/evaluation/relevance-v2-rerun
```

Hardware, library versions, batching and floating-point calculations can affect
scores and tied ranks. Published results are observations, not a bit-for-bit
cross-platform guarantee. The code pins major model/runtime packages but not
every transitive package. Recorded runtime versions are preserved in
[runtime.json](runtime.json).

To regenerate a public-safe export after an evaluation:

```sh
PYTHONPATH=src python3 -m blurag.publication
```

The exporter uses only the standard library. It accepts only the pinned public
dataset checksum, checks query/label/hit consistency, and explicitly selects
published fields. It does not copy arbitrary contents of `.blurag/`.

## Provenance and attribution

- **Dataset:** OTRF Security-Datasets, APT29 emulation day 1, by Roberto Rodriguez
  and the Open Threat Research Forge contributors. Source revision
  `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`;
  [dataset](https://github.com/OTRF/Security-Datasets/tree/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/compound/apt29)
  and [MIT license](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE).
- **Cisco encoder:** [cisco-ai/SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder),
  revision `b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0`, Apache-2.0.
  The authors' retrieval evidence concerns cybersecurity text and Q&A; this
  project evaluates a different, telemetry-oriented task.
- **MiniLM encoder:** [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2),
  Apache-2.0. The runtime uses the
  [Qdrant ONNX conversion](https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx),
  revision `5f1b8cd78bc4fb444dd171e59b18f3a3af89a079`.
- **Runtime projects:** [Sentence Transformers](https://github.com/huggingface/sentence-transformers),
  [Transformers](https://github.com/huggingface/transformers),
  [PyTorch](https://github.com/pytorch/pytorch),
  [FastEmbed](https://github.com/qdrant/fastembed),
  [ONNX Runtime](https://github.com/microsoft/onnxruntime), and
  [Qdrant](https://github.com/qdrant/qdrant). Each retains its own license.

This repository's [Apache-2.0 license](../LICENSE) covers the original project
code and documentation, not a relicensing of these upstream projects, data,
model weights, or trademarks. They are obtained separately during setup.

## Label correction history

An audit of the initial v1 run found that service installation can be represented
by either Security event 4697 or System event 7045. Label revision 2 accepts both
providers for all models without changing the embedded text. The original v1
run is retained locally but is not the published comparison. No query, score,
or model-specific ranking was edited to improve a result.
