"""Verify and unpack a pinned Git archive into one new private scope directory."""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import tarfile

from receipt_store import private, sync_directory


def verified(data, sha256, revision):
    if (not re.fullmatch('[a-f0-9]{64}', sha256) or not re.fullmatch('[a-f0-9]{40}', revision)
            or len(data) > 8 << 20 or hashlib.sha256(data).hexdigest() != sha256):
        raise ValueError('bounded exact source archive and revision required')
    archive = tarfile.open(fileobj=io.BytesIO(data), mode='r:')
    try:
        if archive.pax_headers.get('comment') != revision:
            raise ValueError('Git archive commit disagrees with pinned runtime source')
        members = archive.getmembers()
        if not members or len(members) > 4096 or sum(item.size for item in members) > 16 << 20:
            raise ValueError('bounded source tree required')
        seen = set()
        files = set()
        for item in members:
            name = item.name.rstrip('/')
            path = PurePosixPath(name)
            if (not name or str(path) != name or path.is_absolute() or '..' in path.parts
                    or '.git' in path.parts or name in seen or not (item.isfile() or item.isdir())
                    or item.mode & 0o7000 or item.size < 0 or (item.isdir() and item.size != 0)):
                raise ValueError('regular unique relative source entries without Git metadata required')
            seen.add(name)
            if item.isfile(): files.add(name)
        if any(str(parent) in files for name in seen for parent in PurePosixPath(name).parents):
            raise ValueError('source file conflicts with a parent directory')
        return archive, members
    except Exception:
        archive.close()
        raise


def extract(archive_path, root, sha256, revision):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError('canonical new source destination required')
    private(root.parent, True)
    with Path(archive_path).open('rb') as source:
        data = source.read((8 << 20) + 1)
    archive, members = verified(data, sha256, revision)
    try:
        # Validate the entire archive before creating the destination. Existing
        # paths, links and another writer's tree are never replaced.
        root.mkdir(mode=0o700, exist_ok=False)
        for item in members:
            path = root / item.name.rstrip('/')
            if item.isdir():
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                source = archive.extractfile(item)
                if source is None:
                    raise ValueError('regular source bytes unavailable')
                with source:
                    content = source.read(item.size + 1)
                if len(content) != item.size:
                    raise ValueError('source entry length changed')
                os.fchmod(output.fileno(), 0o755 if item.mode & 0o111 else 0o644)
                output.write(content); output.flush(); os.fsync(output.fileno())
        for directory in sorted((item for item in root.rglob('*') if item.is_dir()),
                                key=lambda item: len(item.parts), reverse=True):
            sync_directory(directory)
        sync_directory(root); sync_directory(root.parent)
        return dict(source_archive_sha256=sha256, source_revision=revision,
                    source_entries=len(members), source_bytes=sum(item.size for item in members),
                    git_metadata_present=False, runtime_started=False)
    finally:
        archive.close()
