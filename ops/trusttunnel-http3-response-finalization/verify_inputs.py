#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path


def verify(root: Path) -> None:
    manifest = json.loads((root / 'manifest.json').read_text())
    for relative, expected in manifest['files_sha256'].items():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('invalid input path')
        actual = hashlib.sha256((root / path).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f'input digest mismatch: {relative}')
    print(f"Verified {len(manifest['files_sha256'])} pinned endpoint inputs")


if __name__ == '__main__':
    verify(Path(__file__).resolve().parent)
