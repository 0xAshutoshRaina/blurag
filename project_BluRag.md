# **Project Blueprint: Offline EDR Telemetry Vector Search**

## **1\. Executive Summary**

This document outlines an exploratory, privacy-first telemetry search Proof of Concept (PoC). Connectivity is allowed to obtain exported logs, software, and model weights. From that point onward, ingestion, vector-store creation, and querying run locally without cloud APIs. P1 is a working vector database and basic search; LLM/agent interpretation is explicitly P2. Performance and retrieval quality are observations to measure, not upfront promises or constraints. See [README.md](README.md) for the runnable P1 implementation.

## **2\. Core Architecture & Workflow**

The system operates strictly within local boundaries (enterprise laptops or isolated SOC servers) using the following pipeline:

> 1. **Connected Acquisition:** Obtain a fixed telemetry snapshot through predefined KQL exports or a public test dataset. Live collection is outside the implemented P1; the starting dataset is recorded OTRF APT29 lab telemetry.  
> 2. **Offline Normalization:** Preserve original JSON and structured device/time fields. Create deterministic, field-labelled text for embedding, with token-aware chunking for long records. Natural-language prose is not mandatory.  
> 3. **Offline Vectorization:** Cisco's Apache-2.0-licensed SecureBERT2.0-biencoder is the default local CPU encoder, using Sentence Transformers and PyTorch without API fees. It produces 768-dimensional vectors. The original MiniLM ONNX baseline remains available in a separate collection; both use float32 vectors.  
> 4. **Local Vector Database:** A self-hosted Qdrant server persists vectors, metadata, and original records. Its Python client's in-process Local mode is not the scale target.  
> 5. **Offline Querying:** Embed query text with the same local model, apply explicit device/time/event filters, and return ranked original events. No generative LLM or agent is required.

## **3\. Performance & Hardware Parameters**

The first implementation runs in CPU-only containers on the available ARM64 Mac with 24 GiB RAM. Dataset size, ingestion time, disk consumption, and query latency will be measured on this hardware. No dedicated GPU is required.

> * **Storage:** Count original records, vector chunks, payloads, and index overhead separately. A Cisco 768-dimensional float32 vector alone occupies 3,072 bytes; that is not the total storage cost of an event. MiniLM's corresponding vector is 1,536 bytes.  
> * **Ingestion:** Stream local files, embed in bounded batches, persist results, and make repeated ingestion idempotent. Cisco starts with a deterministic sample across all devices and event types because its CPU inference is much slower. The original experiment also indexed all 196,081 events with MiniLM; databases are not distributed with the public repository. A full Cisco reindex is explicit.  
> * **Queries:** Separate model startup/query embedding time from database retrieval time. There are no latency targets in P1.

## **4\. Architectural "Gotchas" to Mitigate**

> * **Filtered Retrieval:** Device and time boundaries are explicit database filters. Filtered vector search is distinct from hybrid lexical/vector retrieval, which can be explored later. Semantic similarity alone does not reliably detect obfuscation or prove the absence of threats.  
> * **Evidence Preservation:** Return original records and source references, not invented interpretations. Several chunks from one record should not fill the results with duplicates.  
> * **Offline Boundary:** Preload models and dependencies. Ingestion/query containers use an internal-only network; the separate preparation container has internet connectivity.  
> * **Isolation and Permissions:** Per-investigation stores simplify access control only when the whole investigation shares an authorization boundary. Logs, vectors, and summaries remain sensitive local assets.

## **5\. Prior Art & Existing Open Source Projects**

Relevant references include the following. Their existence is not evidence that this PoC already achieves useful threat-hunting recall:

> * **[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets):** Recorded lab telemetry with documented emulation scenarios; the starting data source for P1.  
> * **[Cisco SecureBERT 2.0 Bi-Encoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder):** Default cybersecurity retrieval encoder, with public Apache-2.0 weights and a 1,024-token Sentence Transformer window.  
> * **[Sentence Transformers](https://github.com/huggingface/sentence-transformers):** Local CPU inference with the publisher's pooling configuration.  
> * **[FastEmbed](https://github.com/qdrant/fastembed):** Preserved MiniLM CPU ONNX baseline.  
> * **[Qdrant](https://github.com/qdrant/qdrant):** Self-hosted vector storage, metadata filtering, and grouped retrieval.  
> * **[MiniLM model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2):** Model dimensions, intended use, and input-window limitations.