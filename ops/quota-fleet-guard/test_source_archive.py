"""Source staging rejects traversal, links and mismatched runtime provenance."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import source_archive as archive

REVISION = 'a' * 40


def fixture(name='tool/run.sh', kind=tarfile.REGTYPE, revision=REVISION):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT,
                      pax_headers={'comment': revision}) as output:
        item = tarfile.TarInfo(name); item.type = kind; item.mode = 0o755
        if kind == tarfile.REGTYPE:
            content = b'fixture source\n'; item.size = len(content)
            output.addfile(item, io.BytesIO(content))
        else:
            item.linkname = '/outside'; output.addfile(item)
    return buffer.getvalue()


class SourceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def extract(self, data, destination=None, revision=REVISION, digest=None):
        path = self.root / 'source.tar'; path.write_bytes(data)
        return archive.extract(path, destination or self.root/'source',
                               digest or hashlib.sha256(data).hexdigest(), revision)

    def test_actual_extraction_preserves_source_and_executable_mode_without_git(self):
        result = self.extract(fixture())
        self.assertEqual(b'fixture source\n', (self.root/'source/tool/run.sh').read_bytes())
        self.assertEqual(0o755, (self.root/'source/tool/run.sh').stat().st_mode & 0o777)
        self.assertFalse(result['git_metadata_present'])
        self.assertFalse(result['runtime_started'])

    def test_traversal_absolute_links_and_git_are_rejected_before_destination_exists(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('/outside', tarfile.REGTYPE),
                           ('a/../outside', tarfile.REGTYPE), ('.git/config', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE), ('link', tarfile.LNKTYPE)]:
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                self.extract(fixture(name, kind))
            self.assertFalse((self.root/'source').exists())

    def test_archive_hash_and_commit_mismatch_leave_no_destination(self):
        for kwargs in ({'digest': 'b'*64}, {'revision': 'b'*40}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): self.extract(fixture(), **kwargs)
            self.assertFalse((self.root/'source').exists())

    def test_existing_destination_and_symlink_are_never_overwritten(self):
        target = self.root/'source'; target.mkdir(mode=0o700)
        marker = target/'keep'; marker.write_text('retained')
        with self.assertRaises(FileExistsError): self.extract(fixture())
        self.assertEqual('retained', marker.read_text())
        link = self.root/'link'; link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError): self.extract(fixture(), link)


if __name__ == '__main__': unittest.main()
