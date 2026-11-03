#!/usr/bin/env python3
"""Offline source-assembly regression checks against a local upstream clone."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import sys
sys.dont_write_bytecode = True

parser = argparse.ArgumentParser()
parser.add_argument("--reference", type=Path, required=True)
parser.add_argument("--h2-crate", type=Path, required=True)
options, unittest_args = parser.parse_known_args()
recipe = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("prepare_source", recipe / "prepare_source.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
manifest = json.loads((recipe / "manifest.json").read_text())


class SourceAssembly(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="guardex-quic-source-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        subprocess.run(["git", "clone", "--quiet", "--shared", "--no-checkout", str(options.reference), str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "checkout", "--quiet", "--detach", manifest["upstream_commit"]], check=True)

    def assert_untouched(self):
        self.assertEqual(module.run("git", "status", "--porcelain", cwd=self.source), "")

    def test_exact_reviewed_source_and_lock(self):
        result = module.prepare(self.source, recipe, options.h2_crate)
        for path, expected in manifest["expected_source_sha256"].items():
            self.assertEqual(module.sha(self.source / path), expected, path)
        self.assertEqual(result["lock_sha256"], manifest["inputs"][manifest["lockfile"]])
        self.assertIn('h2 = { path = "vendor/h2" }', (self.source / "Cargo.toml").read_text())
        for path, expected in manifest["h2"]["patched_source_sha256"].items():
            self.assertEqual(module.sha(self.source / "vendor/h2" / path), expected)
            self.assertNotEqual(expected, manifest["h2"]["pristine_source_sha256"][path])
        module.run("git", "apply", "--reverse", "--check", "--directory=vendor/h2", str(recipe / "inputs" / manifest["h2_patch"]), cwd=self.source)
        with self.assertRaisesRegex(ValueError, "clean"):
            module.prepare(self.source, recipe, options.h2_crate)

    def test_old_vendor_cwd_silent_skip_is_rejected(self):
        original = module.run
        def old_apply(*args, cwd=None):
            if args[:2] == ("git", "apply") and "--directory=vendor/h2" in args and "--check" not in args:
                return original("git", "apply", "--verbose", args[-1], cwd=self.source / "vendor/h2")
            return original(*args, cwd=cwd)
        with mock.patch.object(module, "run", side_effect=old_apply):
            with self.assertRaisesRegex(ValueError, "patched h2 source checksum"):
                module.prepare(self.source, recipe, options.h2_crate)

    def test_canonical_h2_script_applies_backport_in_git_checkout(self):
        patches = self.root / "patches"
        patches.mkdir()
        shutil.copyfile(recipe / "inputs" / manifest["h2_patch"], patches / "h2-capacity.patch")
        shutil.copyfile(recipe / "inputs" / manifest["lockfile"], patches / "endpoint.lock")
        environment = dict(os.environ, GUARDEX_ENDPOINT_SOURCE=str(self.source),
                           GUARDEX_ENDPOINT_PATCHES=str(patches), GUARDEX_H2_ARCHIVE=str(options.h2_crate))
        subprocess.run(["sh", str(recipe.parents[1] / "ops/prepare-h2-capacity.sh")], env=environment, check=True)
        for path, expected in manifest["h2"]["patched_source_sha256"].items():
            self.assertEqual(module.sha(self.source / "vendor/h2" / path), expected)
        module.run("git", "apply", "--reverse", "--check", "--directory=vendor/h2", str(patches / "h2-capacity.patch"), cwd=self.source)
        self.assertEqual(module.sha(self.source / "Cargo.lock"), manifest["inputs"][manifest["lockfile"]])

    def test_tampered_patch_rejected_before_mutation(self):
        altered = self.root / "recipe"
        shutil.copytree(recipe, altered)
        with (altered / "inputs/quic-writable-capacity.patch").open("ab") as output:
            output.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum"):
            module.prepare(self.source, altered, options.h2_crate)
        self.assert_untouched()

    def test_tampered_dependency_rejected_before_mutation(self):
        archive = self.root / "invalid.crate"
        archive.write_bytes(b"not the pinned dependency")
        with self.assertRaisesRegex(ValueError, "archive checksum"):
            module.prepare(self.source, recipe, archive)
        self.assert_untouched()

    def test_wrong_expected_postimage_rejected_before_compilation(self):
        altered = self.root / "recipe"
        shutil.copytree(recipe, altered)
        path = altered / "manifest.json"
        config = json.loads(path.read_text())
        config["expected_source_sha256"]["lib/src/quic_multiplexer.rs"] = "0" * 64
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, "prepared module checksum"):
            module.prepare(self.source, altered, options.h2_crate)

    def test_modified_source_rejected_before_mutation(self):
        target = self.source / "lib/src/quic_multiplexer.rs"
        target.write_text(target.read_text() + "\n// unrelated change\n")
        before = module.sha(target)
        with self.assertRaisesRegex(ValueError, "clean"):
            module.prepare(self.source, recipe, options.h2_crate)
        self.assertEqual(module.sha(target), before)
        self.assertFalse((self.source / "vendor/h2").exists())


if __name__ == "__main__":
    unittest.main(argv=[__file__, *unittest_args])
