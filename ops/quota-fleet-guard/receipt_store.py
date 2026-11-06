"""Private append-only closure receipts with deduplicated native snapshots."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from closure_gate import HOSTS


def private(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OSError('private caller-owned regular path required')


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class ReceiptStore:
    def __init__(self, root):
        self.root = Path(root)
        if not self.root.is_absolute() or self.root.resolve() != self.root:
            raise OSError('canonical private evidence root required')
        private(self.root, True)
        for name in ('receipts', 'native-snapshots'):
            path = self.root / name
            path.mkdir(mode=0o700, exist_ok=True)
            private(path, True)
        sync_directory(self.root)

    def _retain(self, directory, name, data):
        path = directory / name
        if path.exists() or path.is_symlink():
            private(path)
            if path.read_bytes() != data:
                raise OSError('changed retained evidence; never overwrite')
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
            sync_directory(directory)
            return
        temporary = directory / (name + '.tmp-' + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        # Each host has one serialized gate writer. Retain rather than replace
        # another record if an unexpected second writer races this process.
        try:
            os.link(temporary, path)
        except FileExistsError:
            private(path)
            if path.read_bytes() != data:
                raise OSError('concurrent changed evidence; never overwrite')
        temporary.unlink()
        sync_directory(directory)

    def __call__(self, receipt, report):
        host, sequence, digest = receipt['host'], receipt['sequence'], receipt['sha256']
        if (host not in HOSTS or type(sequence) is not int or sequence < 1
                or re.fullmatch('[a-f0-9]{64}', digest) is None):
            raise OSError('invalid retained receipt identity')
        serialized = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False)
        if hashlib.sha256(serialized.encode()).hexdigest() != digest:
            raise OSError('receipt disagrees with actual submitted evidence')
        body = dict(report)
        native = body.get('native_final_file')
        if isinstance(native, str):
            raw = native.encode('utf-8')
            if len(raw) > 8 << 20:
                raise OSError('native snapshot exceeds evidence bound')
            native_digest = hashlib.sha256(raw).hexdigest()
            self._retain(self.root / 'native-snapshots', native_digest + '.json', raw)
            del body['native_final_file']
            body['native_final_blob_sha256'] = native_digest
        record = dict(receipt=receipt, submitted_evidence=body,
                      original_submitted_payload_sha256=digest,
                      native_snapshot_deduplicated=isinstance(native, str))
        data = (json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        self._retain(self.root / 'receipts', f'{host}-{sequence}-{digest}.json', data)
