# Research files

Start with [the findings and method](../EVALUATION.md).

| File | Contents |
|---|---|
| [cases.md](relevance-v2/cases.md) | All 120 queries and first relevant ranks |
| [results.json](relevance-v2/results.json) | Per-query metrics, labels and top-ten source references |
| [provenance.json](relevance-v2/provenance.json) | Dataset checksums and selected source rows |
| [runtime.json](runtime.json) | Recorded hardware and library versions |

`source_record` is a one-based line number in the original dataset; `event_uid`
is the record's content hash. Raw log bodies, credentials, model weights and
vectors are not included.

## Reproduce

After the [initial setup](../README.md#run-it), prepare the second encoder and
run the comparison:

```sh
./blurag --encoder minilm prepare --model-only
./blurag evaluate
```

The evaluator uses separate collections; you do not need to ingest the main
dataset first. Local results and the detailed evidence report go to
`.blurag/evaluation/relevance-v2/`.

Completed runs are cached. For a fresh measurement:

```sh
./blurag evaluate --output-dir .blurag/evaluation/relevance-v2-rerun
```

Hardware and library versions can change scores and tied ranks. This is not a
bit-for-bit cross-platform benchmark.

To regenerate the public tables from the default local run:

```sh
PYTHONPATH=src python3 -m blurag.publication
```

The exporter includes measurements and source references, not log text.

## Sources

- **Data:** Roberto Rodriguez and OTRF's [APT29 day-one telemetry](https://github.com/OTRF/Security-Datasets/tree/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/compound/apt29), under the repository's [MIT license](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE).
- **Cisco:** [SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder), Apache-2.0.
- **MiniLM:** [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2), using [Qdrant's ONNX conversion](https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx), Apache-2.0.

Exact model revisions are in [config.py](../src/blurag/config.py); dataset
revisions and checksums are in [provenance.json](relevance-v2/provenance.json).
These upstream licenses are separate from [this project's license](../LICENSE).
The work is independent and not endorsed by the referenced organizations.
