import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare', ROOT / 'experimental' / 'prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class LockSafetyTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT / 'experimental' / 'manifest.json').read_text())

    def test_research_lock_is_valid_but_cannot_service_an_image(self):
        prepare.validate(self.lock)
        with self.assertRaisesRegex(ValueError, 'review is incomplete'):
            prepare.validate(self.lock, ready=True)

    def test_no_silent_build_edition_or_architecture_substitution(self):
        for key, value in [('build', '26300.9550'), ('edition', 'Professional'), ('architecture', 'arm64'), ('language', 'en-US')]:
            with self.subTest(key=key):
                lock = copy.deepcopy(self.lock)
                lock['target'][key] = value
                with self.assertRaises(ValueError):
                    prepare.validate(lock)

    def test_duplicate_package_and_path_traversal_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock['packages'].append(lock['packages'][0])
        with self.assertRaisesRegex(ValueError, 'Duplicate package'):
            prepare.validate(lock)
        for name in ['../evil.cab', 'a/evil.cab', r'a\evil.cab', '-option.cab']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                prepare.safe_name(name)

    def test_https_origin_is_exact_and_signed_urls_are_not_saved(self):
        prepare.microsoft_url('https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/file.cab')
        for url in ['http://catalog.sf.dl.delivery.mp.microsoft.com/a', 'https://catalog.sf.dl.delivery.mp.microsoft.com.evil.test/a',
                    'https://user:pass@catalog.sf.dl.delivery.mp.microsoft.com/a', 'https://catalog.sf.dl.delivery.mp.microsoft.com/a?token=secret',
                    'https://catalog.sf.dl.delivery.mp.microsoft.com:8443/a']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                prepare.microsoft_url(url)

    def test_readiness_requires_complete_dependency_order(self):
        lock = copy.deepcopy(self.lock)
        lock['status'] = 'ready-for-offline-trial'
        prepare.validate(lock, ready=True)
        for order in [[], ['KB5127753', 'KB5122776'], ['KB5122055', 'KB5127753', 'KB5122776', 'KB5122776'], ['KB5122776', 'KB5122055', 'KB5127753'], ['KB5127753', 'KB5122055', 'KB5122776']]:
            with self.subTest(order=order):
                lock['servicing_order'] = order
                with self.assertRaises(ValueError):
                    prepare.validate(lock, ready=True)

    def test_boolean_flags_cannot_bypass_provenance_or_dependency_review(self):
        for value in ['false', 'true', 0, 1, None]:
            with self.subTest(value=value):
                lock = copy.deepcopy(self.lock)
                lock['base_iso']['official_hash_verified'] = value
                with self.assertRaises(ValueError):
                    prepare.validate(lock)

    def test_streaming_download_rejects_excess_or_short_payload(self):
        for data in [b'1234', b'12']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                prepare.copy_bounded(io.BytesIO(data), io.BytesIO(), 3)
        destination = io.BytesIO()
        prepare.copy_bounded(io.BytesIO(b'123'), destination, 3)
        self.assertEqual(destination.getvalue(), b'123')

    def test_tampered_or_truncated_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.cab'
            path.write_bytes(b'reviewed payload')
            locked = prepare.hashes(path)
            self.assertEqual(prepare.check_file(path, locked), locked)
            path.write_bytes(b'changed! payload')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                prepare.check_file(path, locked)
            path.write_bytes(b'short')
            with self.assertRaisesRegex(ValueError, 'Size mismatch'):
                prepare.check_file(path, locked)


if __name__ == '__main__':
    unittest.main()
