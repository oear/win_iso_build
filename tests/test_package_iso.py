import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "experimental" / "package_iso.py"
SPEC = importlib.util.spec_from_file_location("package_iso", MODULE_PATH)
package_iso = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_iso)


class PackageIsoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Synthetic bytes exercise byte preservation; they are not a bootable ISO.
        self.content = bytes(range(256)) * 3 + b"\x00\xff\x00final-byte"
        self.iso = self.root / "experimental.iso"
        self.iso.write_bytes(self.content)
        self.report = self.root / "build-report.json"
        self.report_data = {
            "status": "offline-image-verified-runtime-pending",
            "iso_sha256": hashlib.sha256(self.content).hexdigest(),
        }
        self.write_report()
        self.delivery = self.root / "parts"

    def write_report(self):
        self.report.write_text(json.dumps(self.report_data), encoding="utf-8-sig")

    def split(self, chunk_size=97):
        return package_iso.split_iso(self.iso, self.delivery, self.report, chunk_size)

    def edit_manifest(self, callback):
        path = self.delivery / "delivery.json"
        delivery = json.loads(path.read_text())
        callback(delivery)
        path.write_text(json.dumps(delivery))

    def test_roundtrip_binary_exact_source_preserved(self):
        for status in package_iso.REPORT_STATUSES:
            with self.subTest(status=status):
                self.report_data["status"] = status
                self.write_report()
                parts_dir = self.root / status
                manifest = package_iso.split_iso(self.iso, parts_dir, self.report, 97)
                data = json.loads(manifest.read_text())
                self.assertEqual(data["build_report"]["status"], status)
                self.assertEqual(data["join_order"], [p["filename"] for p in data["parts"]])
                self.assertTrue(all(p["size"] <= 97 for p in data["parts"]))
                self.assertEqual(b"".join((parts_dir / p["filename"]).read_bytes() for p in data["parts"]), self.content)
                destination = self.root / (status + ".iso")
                result = package_iso.join_iso(manifest, destination)
                self.assertEqual(destination.read_bytes(), self.content)
                self.assertEqual(self.iso.read_bytes(), self.content)
                self.assertEqual(result["sha256"], self.report_data["iso_sha256"])
                self.assertEqual(result["runtime_acceptance"], "pending")
                self.assertIs(result["acceptance_confirmed"], False)

    def test_exact_multiple_and_small_single_part(self):
        for size, chunk, expected in [(12, 4, [4, 4, 4]), (3, 4, [3])]:
            with self.subTest(size=size):
                self.iso.write_bytes(b"x" * size)
                self.report_data["iso_sha256"] = hashlib.sha256(b"x" * size).hexdigest()
                self.write_report()
                manifest = package_iso.split_iso(self.iso, self.root / f"parts-{size}", self.report, chunk)
                self.assertEqual([p["size"] for p in json.loads(manifest.read_text())["parts"]], expected)

    def test_reject_wrong_report_hash_and_status_before_output(self):
        for status, digest in [("running", self.report_data["iso_sha256"]),
                               ("failed-no-accepted-iso", self.report_data["iso_sha256"]),
                               ("offline-image-verified-runtime-pending", "0" * 64),
                               ("native-packages-staged-firstboot-pending", "bad")]:
            with self.subTest(status=status, digest=digest):
                self.report_data.update(status=status, iso_sha256=digest)
                self.write_report()
                with self.assertRaises(ValueError):
                    self.split()
                self.assertFalse(self.delivery.exists())
                self.assertEqual(self.iso.read_bytes(), self.content)

    def test_reject_empty_directory_symlink_and_partial_artifact(self):
        invalid = [self.root / "empty.iso", self.root / "directory.iso", self.root / "unfinished.iso.partial"]
        invalid[0].touch()
        invalid[1].mkdir()
        invalid[2].write_bytes(self.content)
        if hasattr(os, "symlink"):
            link = self.root / "linked.iso"
            try:
                link.symlink_to(self.iso)
                invalid.append(link)
            except OSError:
                pass
        for source in invalid:
            with self.subTest(source=source.name):
                with self.assertRaises((ValueError, OSError)):
                    package_iso.split_iso(source, self.delivery, self.report, 97)
                self.assertFalse(self.delivery.exists())

    def test_never_overwrite_split_or_join(self):
        self.delivery.mkdir()
        sentinel = self.delivery / "keep.txt"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.split()
        self.assertEqual(sentinel.read_bytes(), b"keep")
        manifest = package_iso.split_iso(self.iso, self.root / "new-parts", self.report, 97)
        destination = self.root / "exists.iso"
        destination.write_bytes(b"keep")
        with self.assertRaises(ValueError):
            package_iso.join_iso(manifest, destination)
        self.assertEqual(destination.read_bytes(), b"keep")

    def test_corrupt_missing_truncated_or_symlink_part_rejected(self):
        for mode in ["corrupt", "missing", "truncated", "symlink"]:
            with self.subTest(mode=mode):
                directory = self.root / mode
                manifest = package_iso.split_iso(self.iso, directory, self.report, 97)
                first = directory / "experimental.bin.001"
                if mode == "corrupt":
                    first.write_bytes(b"z" * 97)
                elif mode == "missing":
                    first.unlink()
                elif mode == "truncated":
                    first.write_bytes(b"x")
                else:
                    first.unlink()
                    try:
                        first.symlink_to(self.iso)
                    except OSError:
                        continue
                destination = self.root / (mode + ".iso")
                with self.assertRaises((ValueError, OSError)):
                    package_iso.join_iso(manifest, destination)
                self.assertFalse(destination.exists())
                self.assertEqual(self.iso.read_bytes(), self.content)

    def test_reject_manifest_traversal_reordering_size_and_pass_claim(self):
        mutations = [
            lambda d: d["parts"][0].update(filename="../experimental.iso"),
            lambda d: d["parts"].reverse(),
            lambda d: d["join_order"].reverse(),
            lambda d: d["parts"][0].update(size=True),
            lambda d: d.update(part_size_limit=package_iso.MAX_PART_SIZE + 1),
            lambda d: d.update(acceptance_confirmed=True),
            lambda d: d.update(runtime_acceptance="passed"),
        ]
        manifest = self.split()
        original = manifest.read_bytes()
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                manifest.write_bytes(original)
                self.edit_manifest(mutation)
                destination = self.root / "rejected.iso"
                with self.assertRaises(ValueError):
                    package_iso.join_iso(manifest, destination)
                self.assertFalse(destination.exists())

    def test_join_full_hash_failure_removes_only_own_output(self):
        manifest = self.split()
        self.edit_manifest(lambda d: (d["iso"].update(sha256="0" * 64), d["build_report"].update(iso_sha256="0" * 64)))
        sentinel = self.delivery / "unrelated.txt"
        sentinel.write_bytes(b"keep")
        destination = self.root / "invalid-full-hash.iso"
        with self.assertRaises(ValueError):
            package_iso.join_iso(manifest, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_changed_part_between_precheck_and_join_rejected(self):
        manifest = self.split()
        real_hash_file = package_iso.hash_file
        count = 0
        def mutate_after_precheck(path):
            nonlocal count
            result = real_hash_file(path)
            count += 1
            if count == len(json.loads(manifest.read_text())["parts"]):
                (self.delivery / "experimental.bin.001").write_bytes(b"z" * 97)
            return result
        destination = self.root / "changed.iso"
        with mock.patch.object(package_iso, "hash_file", side_effect=mutate_after_precheck):
            with self.assertRaises(ValueError):
                package_iso.join_iso(manifest, destination)
        self.assertFalse(destination.exists())

    def test_split_failure_cleans_own_outputs_and_preserves_source(self):
        with mock.patch.object(package_iso.os, "fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.split()
        self.assertFalse(self.delivery.exists())
        self.assertEqual(self.iso.read_bytes(), self.content)

    def test_cli_fixed_2000_mib(self):
        with mock.patch.object(package_iso, "split_iso", return_value=self.delivery / "delivery.json") as split:
            self.assertEqual(package_iso.main(["split", "--iso", str(self.iso), "--destination", str(self.delivery), "--report", str(self.report)]), 0)
            self.assertEqual(len(split.call_args.args), 3)
        self.assertEqual(package_iso.MAX_PART_SIZE, 2097152000)

    def test_path_and_fd_metadata_api_differences_are_not_mutation(self):
        real_fstat = package_iso.os.fstat
        def different_representation(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_dev=0, st_ino=0,
                                   st_size=info.st_size,
                                   st_mtime_ns=(info.st_mtime_ns // 1000000000) * 1000000000,
                                   st_ctime_ns=info.st_ctime_ns + 100,
                                   st_file_attributes=0)
        # Model Windows APIs reporting different IDs/precision, with the same
        # independently obtained Win32 identity. No metadata tolerance is added.
        with mock.patch.object(package_iso.os, "fstat", side_effect=different_representation), \
                mock.patch.object(package_iso, "file_identity", return_value=(123, b"a" * 16)):
            with package_iso.open_regular(self.iso) as (source, info):
                self.assertEqual(source.read(), self.content)
                self.assertEqual(info.st_size, len(self.content))

    def test_canonical_identity_mismatch_still_rejected(self):
        with mock.patch.object(package_iso, "file_identity", side_effect=[(1, b"a" * 16), (1, b"b" * 16)]):
            with self.assertRaisesRegex(ValueError, "changed while opening"):
                with package_iso.open_regular(self.iso):
                    self.fail("Identity mismatch must fail before any read")

    def test_read_detects_real_inplace_modification(self):
        before = self.iso.stat()
        with self.assertRaisesRegex(ValueError, "changed while reading"):
            with package_iso.open_regular(self.iso) as (source, _):
                self.assertEqual(source.read(), self.content)
                self.iso.write_bytes(b"z" * len(self.content))
                os.utime(self.iso, ns=(before.st_atime_ns, before.st_mtime_ns + 2000000000))

    def test_read_detects_path_replacement_even_same_bytes_size_and_mtime(self):
        replacement = self.root / "replacement.iso"
        replacement.write_bytes(self.content)
        before = self.iso.stat()
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replaced = False
        try:
            with package_iso.open_regular(self.iso) as (source, _):
                self.assertEqual(source.read(), self.content)
                try:
                    os.replace(replacement, self.iso)
                    replaced = True
                except PermissionError:
                    # Some Windows handle sharing modes prevent replacement;
                    # an OS-enforced refusal also protects the open source.
                    pass
        except ValueError as error:
            self.assertTrue(replaced)
            self.assertIn("changed while reading", str(error))
        else:
            self.assertFalse(replaced, "A replaced path must never pass")

    def test_regular_mode_with_windows_reparse_attribute_rejected(self):
        info = SimpleNamespace(st_mode=self.iso.stat().st_mode, st_file_attributes=0x400)
        with self.assertRaisesRegex(ValueError, "non-reparse"):
            package_iso.require_regular(info, "reparse.iso")

    def test_cleanup_preserves_replacement_with_same_bytes(self):
        target = self.root / "owned-output.iso"
        owned = []
        with target.open("xb") as output:
            package_iso.remember_output(target, output, owned)
            output.write(self.content)
        replacement = self.root / "foreign-output.iso"
        replacement.write_bytes(self.content)
        os.replace(replacement, target)
        package_iso.cleanup_outputs(owned)
        self.assertEqual(target.read_bytes(), self.content)

    @unittest.skipUnless(os.name == "nt", "Win32 handle identity requires an actual Windows host")
    def test_windows_canonical_file_id_matches_path_and_handle(self):
        with self.iso.open("rb") as source:
            by_path = package_iso.file_identity(path=self.iso)
            by_fd = package_iso.file_identity(fd=source.fileno())
            self.assertEqual(by_path, by_fd)
            self.assertEqual(len(by_fd[1]), 16)


if __name__ == "__main__":
    unittest.main()
