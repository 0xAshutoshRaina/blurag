import os
from collections.abc import Sequence

import numpy as np
from tokenizers import Tokenizer

from .config import MINILM, Settings
from .prepare import validate_model


def chunk_text(text: str, tokenizer: Tokenizer, size: int = 224, overlap: int = 32) -> list[str]:
    if size < 1 or not 0 <= overlap < size:
        raise ValueError("Chunk size must be positive, with overlap smaller than size.")
    encoded = tokenizer.encode(text, add_special_tokens=False)
    if not encoded.ids:
        raise ValueError("Cannot embed empty text.")
    chunks = []
    for start in range(0, len(encoded.ids), size - overlap):
        end = min(start + size, len(encoded.ids))
        left = encoded.offsets[start][0]
        right = encoded.offsets[end - 1][1]
        chunks.append(text[left:right])
        if end == len(encoded.ids):
            break
    return chunks


class Embedder:
    def __init__(self, settings: Settings):
        self.encoder = settings.encoder
        validate_model(settings.model_dir, self.encoder)
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
        self.tokenizer = Tokenizer.from_file(str(settings.model_dir / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        if self.encoder == MINILM:
            from fastembed import TextEmbedding

            self.model = TextEmbedding(
                model_name=self.encoder.model_id,
                specific_model_path=str(settings.model_dir),
                cache_dir=str(settings.home / "cache"),
                local_files_only=True,
                providers=["CPUExecutionProvider"],
                threads=settings.threads,
            )
        else:
            import torch
            from sentence_transformers import SentenceTransformer

            torch.set_num_threads(settings.threads)
            self.model = SentenceTransformer(
                str(settings.model_dir),
                device="cpu",
                local_files_only=True,
                trust_remote_code=False,
                model_kwargs={"attn_implementation": "sdpa"},
                config_kwargs={"reference_compile": False},
            )
            if (
                self.model.max_seq_length != self.encoder.max_tokens
                or self.model.get_sentence_embedding_dimension() != self.encoder.dimensions
            ):
                raise ValueError(
                    "The local Sentence Transformer does not match its encoder profile."
                )

    def chunks(self, text: str) -> list[str]:
        return chunk_text(text, self.tokenizer, self.encoder.chunk_tokens, self.encoder.overlap)

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            raise ValueError("Cannot embed an empty batch.")
        for text in texts:
            self.validate_text(text)
        if self.encoder == MINILM:
            vectors = list(self.model.embed(texts, batch_size=len(texts)))
        else:
            vectors = self.model.encode(
                list(texts),
                batch_size=8,
                show_progress_bar=False,
                normalize_embeddings=True,
                convert_to_numpy=True,
            )
        if len(vectors) != len(texts):
            raise ValueError("Embedding count does not match the input count.")
        result = []
        for vector in vectors:
            if vector.shape != (self.encoder.dimensions,) or not np.isfinite(vector).all():
                raise ValueError("Embedding model returned an invalid vector.")
            result.append(vector.tolist())
        return result

    def validate_text(self, text: str) -> None:
        if not text.strip():
            raise ValueError("Embedding text must not be empty.")
        if len(self.tokenizer.encode(text, add_special_tokens=True).ids) > self.encoder.max_tokens:
            raise ValueError(
                f"Text exceeds {self.encoder.model_id}'s {self.encoder.max_tokens}-token window; "
                "shorten the query or reduce the chunk size."
            )

    def query(self, text: str) -> list[float]:
        return self.encode([text])[0]
