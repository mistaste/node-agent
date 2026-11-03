#!/usr/bin/env python3
"""Assemble only the pinned, reviewed endpoint candidate in a clean checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(source, recipe, crate=None):
    manifest = json.loads((recipe / "manifest.json").read_text())
    inputs = recipe / "inputs"
    # Validate every input before making any source changes.
    for name, expected in manifest["inputs"].items():
        path = inputs / name
        if path.parent != inputs or sha(path) != expected:
            raise ValueError("candidate input checksum mismatch: " + path.name)
    if run("git", "rev-parse", "HEAD", cwd=source) != manifest["upstream_commit"]:
        raise ValueError("endpoint checkout is not the pinned upstream revision")
    if run("git", "status", "--porcelain", "--untracked-files=normal", cwd=source):
        raise ValueError("endpoint checkout must be clean")
    if (source / "vendor/h2").exists():
        raise ValueError("pinned dependency destination already exists")
    with tempfile.TemporaryDirectory(prefix="guardex-h2-input-") as directory:
        archive = Path(directory) / "h2.crate"
        if crate is None:
            with urllib.request.urlopen("https://static.crates.io/crates/h2/h2-0.3.27.crate", timeout=30) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError("dependency archive exceeds expected bound")
            archive.write_bytes(data)
        else:
            shutil.copyfile(crate, archive)
        if sha(archive) != manifest["h2"]["crate_sha256"]:
            raise ValueError("pinned h2 archive checksum mismatch")
        for name in manifest["endpoint_patches"]:
            run("git", "apply", "--check", str(inputs / name), cwd=source)
            run("git", "apply", str(inputs / name), cwd=source)
        vendor = source / "vendor/h2"
        vendor.mkdir(parents=True)
        run("tar", "-xzf", str(archive), "--strip-components=1", "-C", str(vendor))
        run("git", "apply", "--check", str(inputs / manifest["h2_patch"]), cwd=vendor)
        run("git", "apply", str(inputs / manifest["h2_patch"]), cwd=vendor)
    with (source / "Cargo.toml").open("a") as output:
        output.write('\n[patch.crates-io]\nh2 = { path = "vendor/h2" }\n')
    shutil.copyfile(inputs / manifest["lockfile"], source / "Cargo.lock")
    return {"upstream": manifest["upstream_commit"], "lock_sha256": sha(source / "Cargo.lock"),
            "quic_sha256": sha(source / "lib/src/quic_multiplexer.rs"),
            "codec_sha256": sha(source / "lib/src/http3_codec.rs")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--recipe", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--h2-crate", type=Path)
    options = parser.parse_args()
    print(json.dumps(prepare(options.source.resolve(), options.recipe.resolve(), options.h2_crate)))
