#!/usr/bin/env python3
"""Validate an experimental lock, or acquire the upstream mirror without running it.

No floating latest URLs, third-party executables, activation or image modifications.
The mirror hash is an integrity reference, not proof of Microsoft provenance/licensing.
"""
import argparse
import hashlib
import json
import re
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

DEFAULT_MANIFEST = Path(__file__).with_name("manifest.json")
HASH = re.compile(r"^[a-f0-9]{64}$")
SHA1 = re.compile(r"^[a-f0-9]{40}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")
MS_HOSTS = {"catalog.sf.dl.delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com", "download.windowsupdate.com"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name):
    require(isinstance(name, str) and SAFE_NAME.fullmatch(name) and ".." not in name,
            "Unsafe filename")


def microsoft_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in MS_HOSTS
            and not parsed.username and not parsed.password and parsed.port in (None, 443),
            "Package URL must be HTTPS on an explicitly allowed Microsoft delivery host")
    require(not parsed.query and not parsed.fragment, "Do not commit temporary signed delivery URLs")


def validate(m, ready=False):
    require(m["schema_version"] == 1 and m["unofficial"] is True, "Unofficial schema v1 required")
    require(m["target"] == {"build": "26340.9616", "edition": "EnterpriseS", "architecture": "x64", "language": "zh-CN"},
            "This trial must not silently substitute another build, edition, language or architecture")
    base = m["base_iso"]
    require(type(base["official_hash_verified"]) is bool, "official_hash_verified must be a boolean")
    require(type(m['dependency_review']['complete']) is bool, 'Dependency review must be a boolean')
    safe_name(base["filename"])
    require(HASH.fullmatch(base["sha256"]) and type(base["size"]) is int and base["size"] > 0, "Invalid base ISO lock")
    require(base["mirror_release"] == "https://github.com/adavak/win_iso_zip/releases/tag/Windows_11_LTSC_2024_X64_ZH-CN", "Unexpected mirror")
    require(len(base["parts"]) == 3, "All three archive parts are required")
    for i, part in enumerate(base["parts"], 1):
        require(part["filename"] == base["filename"].removesuffix(".iso") + f".zip.{i:03d}", "Invalid part sequence")
        require(HASH.fullmatch(part["sha256"]) and type(part["size"]) is int and part["size"] > 0, "Invalid part lock")
    ids = set()
    names = set()
    roles = set()
    for p in m["packages"]:
        require(isinstance(p['id'], str) and re.fullmatch(r'KB[0-9]{7}', p['id']), 'Invalid package ID')
        require(p["id"] not in ids, "Duplicate package ID")
        ids.add(p["id"])
        safe_name(p["filename"])
        require(p["filename"] not in names and p["filename"].lower().endswith((".cab", ".msu")), "Duplicate or invalid package file")
        names.add(p["filename"])
        require(SHA1.fullmatch(p["sha1"]) and type(p["size"]) is int and p["size"] > 0, "Invalid UUP package metadata")
        if p.get("url"):
            microsoft_url(p["url"])
        roles.add(p["role"])
        require(p['role'] in {'checkpoint', 'cumulative', 'enablement'}, 'Unsupported servicing role')
        if ready:
            require(HASH.fullmatch(p.get("sha256") or ""), "Package SHA256 must be reviewed after acquiring the bytes")
            require(p.get("package_identity") and p.get("review_evidence"), "Payload identity and review evidence required")
            require(re.fullmatch(r'Package_for_(?:RollupFix|KB5122776)~31bf3856ad364e35~amd64~~26100\.[0-9]+\.[0-9]+\.[0-9]+', p['package_identity']), 'Invalid package identity')
            require(p["source_host"] == "tlu.dl.delivery.mp.microsoft.com" and p["source_path"].startswith("/filestreamingservice/files/"), "Unexpected UUP delivery origin")
    if ready:
        require(m["status"] == "ready-for-offline-trial" and m["dependency_review"]["complete"] is True,
                "Dependency/payload review is incomplete; offline build is blocked")
        require({"cumulative", "enablement"} <= roles, "Cumulative and enablement packages required")
        order = m["servicing_order"]
        require(order and len(set(order)) == len(order) and set(order) == ids, "Servicing order must cover every reviewed package once")
        require(order == ['KB5122055', 'KB5127753', 'KB5122776'], 'This reviewed checkpoint chain requires KB5122055, KB5127753, then KB5122776')
        require(next(p for p in m["packages"] if p["id"] == order[-1])["role"] == "enablement", "Apply enablement last")
    return m


def hashes(path):
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(4 * 1024 * 1024), b""):
            sha256.update(chunk)
            sha1.update(chunk)
    return {"size": path.stat().st_size, "sha256": sha256.hexdigest(), "sha1": sha1.hexdigest()}


def check_file(path, locked):
    require(path.is_file() and not path.is_symlink(), f"Missing regular file: {path.name}")
    require(path.stat().st_size == locked["size"], f"Size mismatch: {path.name}")
    actual = hashes(path)
    for algorithm in ("sha256", "sha1"):
        if locked.get(algorithm):
            require(actual[algorithm] == locked[algorithm], f"{algorithm} mismatch: {path.name}")
    return actual


def copy_bounded(source, output, expected_size):
    copied = 0
    while True:
        chunk = source.read(min(4 * 1024 * 1024, expected_size - copied + 1))
        if not chunk:
            break
        require(copied + len(chunk) <= expected_size, 'Response exceeds locked size')
        output.write(chunk)
        copied += len(chunk)
    require(copied == expected_size, 'Response is shorter than locked size')


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        # GitHub release assets redirect to this exact CDN; never forward auth.
        require(parsed.scheme == "https" and parsed.hostname in {"github.com", "release-assets.githubusercontent.com"}
                and not parsed.username and not parsed.password and parsed.port in (None, 443), "Untrusted mirror redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Package or metadata redirect is not allowed')


def acquire_packages(m, destination, only_enablement=False):
    selected = [p for p in m['packages'] if not only_enablement or p['role'] == 'enablement']
    require(selected, 'No locked packages selected')
    if all((destination / p['filename']).exists() for p in selected):
        require(not destination.is_symlink(), 'Destination cannot be a symlink')
        return [{'filename': p['filename'], 'source': 'verified-local-cache', **check_file(destination / p['filename'], p)} for p in selected]
    # Fetch fresh expiring URLs into memory. Never persist or print their query.
    api = 'https://api.uupdump.net/get.php?' + urllib.parse.urlencode({
        'id': m['uup']['id'], 'pack': 0, 'edition': 0})
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(api, headers={'User-Agent': 'Mozilla/5.0 LTSC-Experimental-Research'})
    with opener.open(request, timeout=60) as response:
        payload = json.load(response)['response']
    require(payload['build'] == m['target']['build'] and payload['arch'] == 'amd64', 'UUP returned a different build or architecture')
    destination.mkdir(parents=True, exist_ok=True)
    require(not destination.is_symlink(), 'Destination cannot be a symlink')
    results = []
    for p in selected:
        indexed = payload['files'][p['filename']]
        for key in ('sha256', 'sha1', 'size'):
            require(str(indexed[key]) == str(p[key]), 'UUP metadata drift for ' + p['filename'])
        parsed = urllib.parse.urlsplit(indexed['url'])
        require(parsed.hostname == p['source_host'] and parsed.path == p['source_path']
                and parsed.scheme in ('http', 'https') and not parsed.username and not parsed.password
                and parsed.port in (None, 80, 443), 'UUP delivery origin/path drift')
        # Verified for the small EKB only. Other payloads may reject this origin;
        # they then fail without a transport downgrade. Default TLS checks stay on.
        secure_url = urllib.parse.urlunsplit(('https', 'catalog.sf.dl.delivery.mp.microsoft.com', parsed.path, parsed.query, ''))
        path = destination / p['filename']
        if not path.exists():
            partial = path.with_suffix(path.suffix + '.partial')
            require(not partial.exists(), 'Interrupted package download exists: ' + partial.name)
            print('Downloading ' + p['filename'], flush=True)
            try:
                with opener.open(secure_url, timeout=60) as response, partial.open('xb') as output:
                    copy_bounded(response, output, p['size'])
                check_file(partial, p)
                partial.rename(path)
            except urllib.error.HTTPError as error:
                partial.unlink(missing_ok=True)
                # HTTPError may embed the signed URL; report only the status.
                raise ValueError(f'Microsoft HTTPS delivery returned HTTP {error.code}; no HTTP fallback') from None
            except Exception:
                partial.unlink(missing_ok=True)
                raise ValueError('Package acquisition failed; no HTTP fallback and temporary URLs are omitted') from None
        results.append({'filename': p['filename'], **check_file(path, p)})
    require(results, 'No locked packages selected')
    return results


def acquire_base(m, destination):
    base = m["base_iso"]
    destination.mkdir(parents=True, exist_ok=True)
    require(not destination.is_symlink(), "Destination cannot be a symlink")
    iso = destination / base["filename"]
    if iso.exists():
        return check_file(iso, base)
    # Space includes split archive, concatenated ZIP and extracted ISO.
    needed = 2 * sum(p["size"] for p in base["parts"]) + base["size"] + 1024**3
    require(shutil.disk_usage(destination).free >= needed, "Insufficient free space for mirror acquisition")
    opener = urllib.request.build_opener(CheckedRedirect())
    for part in base["parts"]:
        path = destination / part["filename"]
        if not path.exists():
            partial = path.with_suffix(path.suffix + ".partial")
            require(not partial.exists(), f"Remove or inspect interrupted download: {partial.name}")
            url = base["mirror_release"].replace("/tag/", "/download/") + "/" + part["filename"]
            print("Downloading " + part["filename"], flush=True)
            try:
                with opener.open(url, timeout=60) as response, partial.open("xb") as output:
                    copy_bounded(response, output, part['size'])
                check_file(partial, part)
                partial.rename(path)
            except Exception:
                partial.unlink(missing_ok=True)
                raise
        check_file(path, part)
    archive = destination / "base-media.zip"
    require(not archive.exists(), "Concatenated archive already exists; inspect it before retrying")
    try:
        with archive.open("xb") as output:
            for part in base["parts"]:
                with (destination / part["filename"]).open("rb") as source:
                    copy_bounded(source, output, part['size'])
        partial_iso = iso.with_suffix(".iso.partial")
        require(not partial_iso.exists(), "ISO partial already exists")
        with zipfile.ZipFile(archive) as z:
            require(z.namelist() == [base["filename"]], "Mirror ZIP must contain exactly the locked ISO")
            info = z.getinfo(base["filename"])
            require(info.file_size == base["size"], "Unexpected uncompressed ISO size")
            with z.open(info) as source, partial_iso.open("xb") as output:
                copy_bounded(source, output, base['size'])
        actual = check_file(partial_iso, base)
        partial_iso.rename(iso)
        return actual
    finally:
        archive.unlink(missing_ok=True)
        if 'partial_iso' in locals():
            partial_iso.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "acquire-base", "acquire-packages"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-build-ready", action="store_true")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--only-enablement", action="store_true")
    args = parser.parse_args()
    try:
        m = validate(json.loads(args.manifest.read_text(encoding="utf-8")), args.require_build_ready)
        if args.command == "acquire-base":
            require(args.destination is not None, "--destination is required")
            actual = acquire_base(m, args.destination)
            print(json.dumps({"integrity": "matches upstream mirror lock", "microsoft_provenance": "not independently verified", **actual}, indent=2))
        elif args.command == "acquire-packages":
            require(args.destination is not None, "--destination is required")
            print(json.dumps(acquire_packages(m, args.destination, args.only_enablement), indent=2))
        else:
            print(json.dumps({"valid": True, "status": m["status"], "build_ready": args.require_build_ready}))
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
