import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

PIPELINE_VERSION = "v1"


@dataclass(frozen=True)
class EncoderSpec:
    key: str
    model_id: str
    repository: str
    revision: str
    files: tuple[str, ...]
    dimensions: int
    max_tokens: int
    chunk_tokens: int
    overlap: int
    directory: str
    collection: str

    @property
    def vector_name(self) -> str:
        return f"{self.key}_{self.revision[:12]}_{PIPELINE_VERSION}"


MINILM = EncoderSpec(
    key="minilm",
    model_id="sentence-transformers/all-MiniLM-L6-v2",
    repository="Qdrant/all-MiniLM-L6-v2-onnx",
    revision="5f1b8cd78bc4fb444dd171e59b18f3a3af89a079",
    files=(
        "model.onnx",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "vocab.txt",
        "README.md",
    ),
    dimensions=384,
    max_tokens=256,
    chunk_tokens=224,
    overlap=32,
    directory="model",
    collection="blurag_events",
)
SECUREBERT = EncoderSpec(
    key="securebert",
    model_id="cisco-ai/SecureBERT2.0-biencoder",
    repository="cisco-ai/SecureBERT2.0-biencoder",
    revision="b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0",
    files=(
        "model.safetensors",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "modules.json",
        "1_Pooling/config.json",
        "config_sentence_transformers.json",
        "sentence_bert_config.json",
        "README.md",
    ),
    dimensions=768,
    max_tokens=1024,
    chunk_tokens=960,
    overlap=64,
    directory="securebert-model",
    collection="blurag_securebert",
)
ENCODERS = {spec.key: spec for spec in (SECUREBERT, MINILM)}


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".part")
    try:
        temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Settings:
    home: Path
    url: str
    collection: str = SECUREBERT.collection
    threads: int = 4
    encoder: EncoderSpec = SECUREBERT

    @classmethod
    def from_env(cls, collection: str | None = None, encoder: str = SECUREBERT.key) -> "Settings":
        if encoder not in ENCODERS:
            raise ValueError(f"Unknown encoder: {encoder}")
        spec = ENCODERS[encoder]
        url = os.environ.get("BLURAG_QDRANT_URL", "http://127.0.0.1:6333")
        parsed = urlparse(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1", "qdrant"}
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("BLURAG_QDRANT_URL must name localhost or the local qdrant service.")
        threads = int(os.environ.get("BLURAG_THREADS", "4"))
        if threads < 1:
            raise ValueError("BLURAG_THREADS must be positive.")
        return cls(
            home=Path(os.environ.get("BLURAG_HOME", ".blurag")),
            url=url,
            collection=collection if collection is not None else spec.collection,
            threads=threads,
            encoder=spec,
        )

    @property
    def model_dir(self) -> Path:
        return self.home / self.encoder.directory
