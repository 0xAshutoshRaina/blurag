import json
import shutil
import sys
import zipfile
from pathlib import Path

import requests

from .config import (
    EncoderSpec,
    Settings,
    file_sha256,
    write_json,
)

DATA_REVISION = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
DATA_BASE = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{DATA_REVISION}"
ARCHIVE_NAME = "apt29_evals_day1_manual.zip"
ARCHIVE_SHA256 = "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5"
ARCHIVE_MEMBER = "apt29_evals_day1_manual_2020-05-01225525.json"
DATA_URL = f"{DATA_BASE}/datasets/compound/apt29/day1/{ARCHIVE_NAME}"


def download(url: str, destination: Path, expected_sha256: str | None = None) -> None:
    if destination.exists() and expected_sha256:
        if file_sha256(destination) != expected_sha256:
            raise ValueError(f"Checksum mismatch for {destination}; move it aside before retrying.")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    print(f"Downloading {destination.name}", file=sys.stderr)
    try:
        with requests.get(url, stream=True, timeout=(15, 180)) as response:
            response.raise_for_status()
            with temporary.open("wb") as stream:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    stream.write(chunk)
        if expected_sha256 and file_sha256(temporary) != expected_sha256:
            raise ValueError(f"Downloaded checksum mismatch: {url}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def validate_model(model_dir: Path, encoder: EncoderSpec) -> dict:
    manifest_path = model_dir / "manifest.json"
    if not manifest_path.exists():
        raise ValueError("Local model is not prepared. Run ./blurag prepare while connected first.")
    manifest = json.loads(manifest_path.read_text())
    if (
        manifest.get("model_id") != encoder.model_id
        or manifest.get("revision") != encoder.revision
        or set(manifest.get("sha256", {})) != set(encoder.files)
    ):
        raise ValueError("Local model manifest does not match this pipeline.")
    for name in encoder.files:
        path = model_dir / name
        if not path.is_file() or file_sha256(path) != manifest["sha256"][name]:
            raise ValueError(f"Missing or modified model file: {path}. No online fallback is used.")
    return manifest


def prepare(settings: Settings, data_dir: Path, *, model_only: bool = False) -> dict:
    model_dir = settings.model_dir
    encoder = settings.encoder
    if (model_dir / "manifest.json").exists():
        model_manifest = validate_model(model_dir, encoder)
    else:
        for name in encoder.files:
            download(
                f"https://huggingface.co/{encoder.repository}/resolve/{encoder.revision}/{name}",
                model_dir / name,
            )
        model_manifest = {
            "model_id": encoder.model_id,
            "repository": encoder.repository,
            "revision": encoder.revision,
            "license": "Apache-2.0",
            "sha256": {name: file_sha256(model_dir / name) for name in encoder.files},
        }
        write_json(model_dir / "manifest.json", model_manifest)
    if model_only:
        return {"model": model_manifest, "model_dir": str(model_dir)}

    archive_path = data_dir / "downloads" / ARCHIVE_NAME
    download(DATA_URL, archive_path, ARCHIVE_SHA256)
    destination = data_dir / "apt29-day1.jsonl"
    manifest_path = data_dir / "dataset-manifest.json"
    if destination.exists():
        if not manifest_path.exists():
            raise ValueError(f"Refusing to overwrite {destination} without its dataset manifest.")
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("archive_sha256") != ARCHIVE_SHA256 or file_sha256(
            destination
        ) != manifest.get("jsonl_sha256"):
            raise ValueError(f"Dataset checksum mismatch: {destination}")
    else:
        temporary = destination.with_suffix(".jsonl.part")
        try:
            with zipfile.ZipFile(archive_path) as archive:
                member = archive.getinfo(ARCHIVE_MEMBER)
                if member.file_size > 512 * 1024 * 1024:
                    raise ValueError("Dataset member exceeds the expected extraction size.")
                with archive.open(member) as source, temporary.open("wb") as target:
                    shutil.copyfileobj(source, target)
            with temporary.open("rb") as stream:
                records = sum(bool(line.strip()) for line in stream)
            manifest = {
                "name": "OTRF APT29 emulation, day 1",
                "kind": "Recorded Windows lab telemetry, not production or fabricated events",
                "source_url": DATA_URL,
                "source_revision": DATA_REVISION,
                "license": "MIT",
                "archive_sha256": ARCHIVE_SHA256,
                "archive_member": ARCHIVE_MEMBER,
                "jsonl_sha256": file_sha256(temporary),
                "records": records,
                "bytes": temporary.stat().st_size,
            }
            temporary.replace(destination)
            write_json(manifest_path, manifest)
        finally:
            temporary.unlink(missing_ok=True)
    download(f"{DATA_BASE}/LICENSE", data_dir / "OTRF-LICENSE.txt")
    download(
        f"{DATA_BASE}/datasets/compound/apt29/README.md",
        data_dir / "OTRF-DATASET-README.md",
    )
    return {"model": model_manifest, "dataset": manifest, "input_file": str(destination)}
