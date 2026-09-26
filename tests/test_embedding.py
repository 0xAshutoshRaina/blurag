import json

import pytest
from tokenizers import Tokenizer, models, pre_tokenizers

from blurag.config import MINILM, SECUREBERT, Settings, file_sha256
from blurag.embedding import chunk_text
from blurag.prepare import validate_model


@pytest.fixture
def tokenizer():
    value = Tokenizer(models.WordLevel({"[UNK]": 0, "alpha": 1, "beta": 2}, unk_token="[UNK]"))
    value.pre_tokenizer = pre_tokenizers.Whitespace()
    return value


def test_long_text_is_chunked_without_losing_the_tail(tokenizer):
    text = "alpha beta " * 500 + "TAIL_MARKER"
    chunks = chunk_text(text, tokenizer)
    assert len(chunks) > 1
    assert chunks[-1].endswith("TAIL_MARKER")
    assert all(len(tokenizer.encode(chunk).ids) <= 224 for chunk in chunks)
    assert chunks[0] == text[: len(chunks[0])]


def test_short_text_is_not_duplicated(tokenizer):
    assert chunk_text("alpha beta", tokenizer) == ["alpha beta"]
    with pytest.raises(ValueError, match="empty"):
        chunk_text(" ", tokenizer)
    with pytest.raises(ValueError, match="Chunk size"):
        chunk_text("alpha", tokenizer, size=32, overlap=32)


@pytest.mark.parametrize("encoder", [MINILM, SECUREBERT])
def test_model_manifest_checks_every_file(tmp_path, encoder):
    for name in encoder.files:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(name)
    manifest = {
        "model_id": encoder.model_id,
        "revision": encoder.revision,
        "sha256": {name: file_sha256(tmp_path / name) for name in encoder.files},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    assert validate_model(tmp_path, encoder) == manifest
    (tmp_path / encoder.files[0]).write_text("changed")
    with pytest.raises(ValueError, match="modified model file"):
        validate_model(tmp_path, encoder)


def test_missing_model_has_no_download_fallback(tmp_path):
    with pytest.raises(ValueError, match="prepare"):
        validate_model(tmp_path, SECUREBERT)


def test_encoder_profiles_preserve_the_old_collection_and_use_a_new_default():
    cisco = Settings.from_env()
    baseline = Settings.from_env(encoder="minilm")
    assert cisco.encoder == SECUREBERT
    assert cisco.collection == "blurag_securebert"
    assert baseline.collection == "blurag_events"
    assert baseline.model_dir.name == "model"
    assert baseline.encoder.vector_name == "minilm_5f1b8cd78bc4_v1"
    assert cisco.model_dir != baseline.model_dir
    assert Settings.from_env("my_case", encoder="securebert").collection == "my_case"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org:6333",
        "http://example.org:6333",
        "http://user:password@localhost:6333",
        "http://localhost:6333/cloud",
    ],
)
def test_remote_or_ambiguous_qdrant_urls_are_rejected(monkeypatch, url):
    monkeypatch.setenv("BLURAG_QDRANT_URL", url)
    with pytest.raises(ValueError, match="must name localhost"):
        Settings.from_env()
