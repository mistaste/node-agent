import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from closure_gate import ClosureGate
from receipt_store import ReceiptStore
from test_closure_gate import fixture, report, NOW


class StoreTests(unittest.TestCase):
    def test_actual_private_files_and_native_dedup_preserve_each_sequence(self):
        config, tokens = fixture(); host = sorted(config['hosts'])[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            gate = ClosureGate(config, ReceiptStore(root))
            gate.submit(host, tokens[host], report(config, host), NOW)
            gate.submit(host, tokens[host], report(config, host, sequence=2, observed=NOW + 1), NOW + 1)
            files = list((root / 'receipts').iterdir())
            self.assertEqual(2, len(files))
            # Snapshot bytes are identical while the observations/receipts differ.
            self.assertEqual(1, len(list((root / 'native-snapshots').iterdir())))
            for path in [*files, *(root / 'native-snapshots').iterdir()]:
                self.assertEqual(0, path.stat().st_mode & 0o077)
            record = json.loads(files[0].read_text())
            self.assertNotIn('native_final_file', record['submitted_evidence'])
            digest = record['submitted_evidence']['native_final_blob_sha256']
            self.assertEqual(digest, hashlib.sha256((root / 'native-snapshots' / (digest + '.json')).read_bytes()).hexdigest())

    def test_changed_native_blob_is_never_overwritten_or_published(self):
        config, tokens = fixture(); host = sorted(config['hosts'])[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            gate = ClosureGate(config, ReceiptStore(root))
            gate.submit(host, tokens[host], report(config, host), NOW)
            blob = next((root / 'native-snapshots').iterdir()); blob.write_text('changed')
            with self.assertRaises(OSError):
                gate.submit(host, tokens[host], report(config, host, sequence=2, observed=NOW + 1), NOW + 1)
            self.assertEqual('changed', blob.read_text())
            self.assertNotIn(host, gate.reports)
            self.assertEqual(1, len(list((root / 'receipts').iterdir())))

    def test_actual_append_survives_new_gate_without_overwriting_history(self):
        config, tokens = fixture(); host = sorted(config['hosts'])[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            ClosureGate(config, ReceiptStore(root)).submit(host, tokens[host], report(config, host), NOW)
            path = next((root / 'receipts').iterdir()); original = path.read_bytes()
            second = ClosureGate(config, ReceiptStore(root))
            second.submit(host, tokens[host], report(config, host), NOW + 1)
            self.assertEqual(original, path.read_bytes())
            self.assertEqual(1, len(list((root / 'receipts').iterdir())))

    def test_symlink_evidence_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as other:
            root = Path(temporary).resolve(); root.chmod(0o700)
            (root / 'receipts').symlink_to(Path(other).resolve(), target_is_directory=True)
            with self.assertRaises(OSError): ReceiptStore(root)


if __name__ == '__main__':
    unittest.main()
