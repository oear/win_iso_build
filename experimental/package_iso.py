#!/usr/bin/env python3
"""Split/join a completed experimental ISO locally, without compression or upload.

Only a build report with an explicitly pending runtime status can authorize
packaging. Hash matching establishes byte integrity, not ISO bootability,
Microsoft provenance, licensing, or installed-system acceptance.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

MAX_PART_SIZE = 2000 * 1024 * 1024
BUFFER_SIZE = 4 * 1024 * 1024
REPORT_STATUSES = {
    "offline-image-verified-runtime-pending",
    "native-packages-staged-firstboot-pending",
}
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
UNSAFE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
DEVICE_NAME = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_leaf(name):
    require(isinstance(name, str) and name not in {"", ".", ".."}
            and not UNSAFE_NAME.search(name) and not DEVICE_NAME.match(name)
            and not name.endswith((".", " ")), "Unsafe or nonportable filename")
    return name


def digest_value(value):
    require(isinstance(value, str) and SHA256.fullmatch(value), "Invalid SHA256")
    return value.lower()


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def open_regular(path):
    """Reject symlinks, devices, directories, and changes during a read."""
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), f"Not a regular file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        require(stat.S_ISREG(opened.st_mode) and snapshot(opened) == snapshot(before),
                f"File changed while opening: {path.name}")
        yield source, opened
        require(snapshot(os.fstat(source.fileno())) == snapshot(opened)
                and snapshot(path.lstat()) == snapshot(opened),
                f"File changed while reading: {path.name}")


def hash_stream(source):
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: source.read(BUFFER_SIZE), b""):
        digest.update(block)
        size += len(block)
    return size, digest.hexdigest()


def hash_file(path):
    with open_regular(path) as (source, info):
        size, digest = hash_stream(source)
        require(size == info.st_size, f"Incomplete file read: {Path(path).name}")
    return size, digest


def read_json(path):
    with open_regular(path) as (source, info):
        require(0 < info.st_size <= 1024 * 1024, "JSON must be a nonempty file of at most 1 MiB")
        raw = source.read()
        require(len(raw) == info.st_size, "Incomplete JSON read")
    value = json.loads(raw.decode("utf-8-sig"))
    require(isinstance(value, dict), "JSON root must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def remember_output(path, output, owned):
    info = os.fstat(output.fileno())
    owned.append((Path(path), info.st_dev, info.st_ino))


def cleanup_outputs(owned):
    """Never remove an existing/unrecognized file or recursively erase a folder."""
    for path, device, inode in reversed(owned):
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == (device, inode):
                path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # An incomplete delivery never has a success return. Leave evidence
            # rather than deleting content whose ownership cannot be checked.
            pass


def split_iso(iso, destination, report, chunk_size=MAX_PART_SIZE):
    """The smaller chunk override exists only for local function-level tests."""
    iso, destination, report = Path(iso), Path(destination), Path(report)
    safe_leaf(iso.name)
    require(iso.suffix.lower() == ".iso", "Input must be a completed .iso file, not a partial/download artifact")
    require(type(chunk_size) is int and 0 < chunk_size <= MAX_PART_SIZE, "Invalid part size")
    build, report_sha256 = read_json(report)
    require(build.get("status") in REPORT_STATUSES, "Build report status does not authorize ISO packaging")
    expected = digest_value(build.get("iso_sha256"))
    owned = []
    created_directory = False
    try:
        with open_regular(iso) as (source, info):
            require(info.st_size > 0, "ISO must not be empty")
            size, source_digest = hash_stream(source)
            require(size == info.st_size and source_digest == expected,
                    "Full ISO SHA256 does not match build-report.iso_sha256")
            if "iso_size" in build:
                require(type(build["iso_size"]) is int and build["iso_size"] == size,
                        "ISO size does not match build report")
            # mkdir and xb are exclusive: existing paths, including symlinks,
            # are never overwritten. The caller must provide an existing parent.
            destination.mkdir()
            created_directory = True
            source.seek(0)
            copied_digest = hashlib.sha256()
            parts = []
            remaining = size
            while remaining:
                index = len(parts) + 1
                part_name = safe_leaf(f"{iso.stem}.bin.{index:03d}")
                part_path = destination / part_name
                part_size = min(chunk_size, remaining)
                part_digest = hashlib.sha256()
                with part_path.open("xb") as output:
                    remember_output(part_path, output, owned)
                    left = part_size
                    while left:
                        block = source.read(min(BUFFER_SIZE, left))
                        require(bool(block), "ISO truncated while splitting")
                        output.write(block)
                        part_digest.update(block)
                        copied_digest.update(block)
                        left -= len(block)
                    output.flush()
                    os.fsync(output.fileno())
                parts.append({"index": index, "filename": part_name,
                              "size": part_size, "sha256": part_digest.hexdigest()})
                remaining -= part_size
            require(not source.read(1) and copied_digest.hexdigest() == source_digest,
                    "ISO changed while splitting; delivery rejected")
        for part in parts:
            written_size, written_digest = hash_file(destination / part["filename"])
            require(written_size == part["size"] and written_digest == part["sha256"],
                    f"Written part hash/size mismatch: {part['filename']}")
        manifest = {
            "schema_version": 1,
            "format": "raw-binary-split",
            "iso": {"filename": iso.name, "size": size, "sha256": source_digest},
            "part_size_limit": chunk_size,
            "join_order": [part["filename"] for part in parts],
            "parts": parts,
            "build_report": {"filename": report.name, "sha256": report_sha256,
                             "status": build["status"], "iso_sha256": expected},
            "runtime_acceptance": "pending",
            "acceptance_confirmed": False,
            "note": "Byte integrity only. Nonofficial experimental media; first boot and installed-system acceptance remain pending.",
        }
        manifest_path = destination / "delivery.json"
        raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        with manifest_path.open("xb") as output:
            remember_output(manifest_path, output, owned)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        return manifest_path
    except BaseException:
        cleanup_outputs(owned)
        if created_directory:
            try:
                destination.rmdir()
            except OSError:
                pass
        raise


def validate_delivery(delivery):
    require(type(delivery.get("schema_version")) is int and delivery["schema_version"] == 1
            and delivery.get("format") == "raw-binary-split", "Unsupported delivery manifest")
    require(delivery.get("runtime_acceptance") == "pending"
            and delivery.get("acceptance_confirmed") is False, "Manifest must preserve pending runtime acceptance")
    iso, build, parts = delivery.get("iso"), delivery.get("build_report"), delivery.get("parts")
    require(isinstance(iso, dict) and isinstance(build, dict) and isinstance(parts, list), "Missing delivery fields")
    safe_leaf(iso.get("filename"))
    require(Path(iso["filename"]).suffix.lower() == ".iso", "Manifest does not describe an ISO")
    require(type(iso.get("size")) is int and iso["size"] > 0, "Invalid ISO size")
    iso_digest = digest_value(iso.get("sha256"))
    require(build.get("status") in REPORT_STATUSES and digest_value(build.get("iso_sha256")) == iso_digest,
            "Build report status/hash does not match the delivery ISO")
    digest_value(build.get("sha256"))
    limit = delivery.get("part_size_limit")
    require(type(limit) is int and 0 < limit <= MAX_PART_SIZE, "Part limit exceeds 2000 MiB")
    require(len(parts) == (iso["size"] + limit - 1) // limit and 0 < len(parts) <= 10000,
            "Incorrect number of parts")
    remaining = iso["size"]
    names = []
    for index, part in enumerate(parts, 1):
        require(isinstance(part, dict) and type(part.get("index")) is int and part["index"] == index,
                "Part indices must be consecutive and ordered")
        name = safe_leaf(part.get("filename"))
        require(name == f"{Path(iso['filename']).stem}.bin.{index:03d}", "Unexpected part name/order")
        require(type(part.get("size")) is int and part["size"] == min(limit, remaining), "Invalid part size")
        digest_value(part.get("sha256"))
        names.append(name)
        remaining -= part["size"]
    require(remaining == 0 and delivery.get("join_order") == names, "Join order or total size mismatch")
    return iso, parts


def join_iso(manifest, destination):
    manifest, destination = Path(manifest), Path(destination)
    safe_leaf(destination.name)
    require(destination.suffix.lower() == ".iso", "Destination must be a new .iso file")
    # lexists also rejects a dangling symlink without following it.
    require(not os.path.lexists(str(destination)), "Destination already exists; no overwrite allowed")
    delivery, _ = read_json(manifest)
    iso, parts = validate_delivery(delivery)
    for part in parts:
        size, digest = hash_file(manifest.parent / part["filename"])
        require(size == part["size"] and digest == digest_value(part["sha256"]),
                f"Part hash/size mismatch: {part['filename']}")
    owned = []
    try:
        total_digest = hashlib.sha256()
        total_size = 0
        with destination.open("xb") as output:
            remember_output(destination, output, owned)
            for part in parts:
                part_digest = hashlib.sha256()
                copied = 0
                with open_regular(manifest.parent / part["filename"]) as (source, _):
                    for block in iter(lambda: source.read(BUFFER_SIZE), b""):
                        output.write(block)
                        part_digest.update(block)
                        total_digest.update(block)
                        copied += len(block)
                require(copied == part["size"] and part_digest.hexdigest() == digest_value(part["sha256"]),
                        f"Part changed after verification: {part['filename']}")
                total_size += copied
            output.flush()
            os.fsync(output.fileno())
        expected = digest_value(iso["sha256"])
        require(total_size == iso["size"] and total_digest.hexdigest() == expected,
                "Rejoined ISO full hash/size mismatch")
        # Independently read the written bytes, not just the input stream digest.
        written_size, written_digest = hash_file(destination)
        require(written_size == iso["size"] and written_digest == expected,
                "Written ISO full hash/size mismatch")
        return {"filename": destination.name, "size": written_size, "sha256": written_digest,
                "runtime_acceptance": "pending", "acceptance_confirmed": False}
    except BaseException:
        cleanup_outputs(owned)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    split = commands.add_parser("split", help="Split an ISO into raw parts of at most 2000 MiB")
    split.add_argument("--iso", required=True, type=Path)
    split.add_argument("--destination", required=True, type=Path, help="New directory; parent must exist")
    split.add_argument("--report", required=True, type=Path)
    join = commands.add_parser("join", help="Verify every part, join, then verify the written ISO")
    join.add_argument("--manifest", required=True, type=Path)
    join.add_argument("--destination", required=True, type=Path, help="New ISO; parent must exist")
    args = parser.parse_args(argv)
    try:
        if args.command == "split":
            result = {"manifest": str(split_iso(args.iso, args.destination, args.report)),
                      "runtime_acceptance": "pending", "acceptance_confirmed": False}
        else:
            result = join_iso(args.manifest, args.destination)
    except (OSError, ValueError, TypeError) as error:
        print(f"Packaging rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
