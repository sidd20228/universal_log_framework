#!/usr/bin/env python3
"""Verify and optionally extract a ULPF offline release without an engine."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


MANIFEST_VERSION = "ulpf-offline-bundle/1.1.0"
REQUIRED_ROLES = {
    "image.ulpf", "image.clickhouse", "compose", "config", "migration.clickhouse",
    "documentation", "license", "schema", "verifier",
}
ALLOWED_ROLES = REQUIRED_ROLES | {"sbom", "vulnerability_report", "notice", "signature"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ROOT_PATTERN = re.compile(r"^ulpf-offline-([0-9A-Za-z][0-9A-Za-z.+_-]{0,127})-(amd64|arm64)$")
MAX_MEMBERS = 200_000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_IMAGE_JSON_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = int(os.environ.get("ULPF_OFFLINE_MAX_ARCHIVE_BYTES", str(32 * 1024 * 1024 * 1024)))
IMAGE_TAG_PATTERN = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$")


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"manifest contains duplicate key {key!r}")
        result[key] = value
    return result


def decode_json(body, label):
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")


def safe_member_name(name):
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        fail(f"unsafe archive path {name!r}")
    stripped = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(stripped)
    if not path.parts or any(part in ("", ".", "..") for part in path.parts) or path.as_posix() != stripped:
        fail(f"non-canonical archive path {name!r}")
    return path


def safe_payload_path(value):
    if not isinstance(value, str) or not value or value.endswith("/"):
        fail(f"invalid artifact path {value!r}")
    path = safe_member_name(value)
    if len(path.parts) < 2:
        return path
    return path


def digest_stream(stream, limit=None, output=None):
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if limit is not None and size > limit:
            fail("archive content exceeds configured size limit")
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    return digest.hexdigest(), size


def verify_sidecar(archive_path):
    sidecar = Path(str(archive_path) + ".sha256")
    if not sidecar.exists():
        return False
    if sidecar.is_symlink() or not sidecar.is_file():
        fail("archive checksum sidecar is not a regular file")
    if sidecar.stat().st_size > 1024:
        fail("archive checksum sidecar is unexpectedly large")
    try:
        line = sidecar.read_text(encoding="ascii").strip()
    except UnicodeDecodeError:
        fail("archive checksum sidecar is not ASCII")
    match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
    if match is None or match.group(2) != archive_path.name:
        fail("archive checksum sidecar is malformed or names another file")
    with archive_path.open("rb") as stream:
        actual, _ = digest_stream(stream, MAX_ARCHIVE_BYTES)
    if actual != match.group(1):
        fail("archive checksum does not match its sidecar")
    return True


def materialize_tar(archive_path, temporary):
    if archive_path.name.endswith(".tar.zst"):
        zstd = shutil.which("zstd")
        if zstd is None:
            fail("zstd is required to verify a .tar.zst archive")
        target = Path(temporary) / "bundle.tar"
        process = subprocess.Popen([zstd, "--decompress", "--stdout", str(archive_path)], stdout=subprocess.PIPE)
        try:
            with target.open("xb") as output:
                _, size = digest_stream(process.stdout, MAX_ARCHIVE_BYTES, output)
            return_code = process.wait()
            if return_code != 0:
                fail("zstd decompression failed")
            if size == 0:
                fail("decompressed archive is empty")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        return target
    if archive_path.name.endswith(".tar"):
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            fail("archive exceeds configured size limit")
        return archive_path
    fail("archive name must end in .tar or .tar.zst")


def read_member(archive, member, maximum=None):
    if maximum is not None and member.size > maximum:
        fail(f"archive member {member.name!r} exceeds its size limit")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read archive member {member.name!r}")
    body = stream.read((maximum + 1) if maximum is not None else -1)
    if maximum is not None and len(body) > maximum:
        fail(f"archive member {member.name!r} exceeds its size limit")
    if len(body) != member.size:
        fail(f"archive member {member.name!r} is truncated")
    return body


def inventory_archive(archive):
    members = archive.getmembers()
    if len(members) > MAX_MEMBERS:
        fail("archive contains too many members")
    seen = {}
    roots = set()
    declared_total = 0
    for member in members:
        path = safe_member_name(member.name)
        canonical = path.as_posix()
        if canonical in seen:
            fail(f"archive contains duplicate path {canonical!r}")
        seen[canonical] = member
        roots.add(path.parts[0])
        if member.pax_headers:
            fail(f"archive member {canonical!r} contains unsupported PAX metadata")
        if not (member.isdir() or member.isreg()):
            fail(f"archive member {canonical!r} is a link or special file")
        if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
            fail(f"archive member {canonical!r} has non-canonical ownership")
        if member.mtime < 0:
            fail(f"archive member {canonical!r} has a negative timestamp")
        if member.isdir() and member.mode != 0o755:
            fail(f"archive directory {canonical!r} has mode {member.mode:o}, want 755")
        if member.isreg() and member.mode not in (0o644, 0o755):
            fail(f"archive file {canonical!r} has unsupported mode {member.mode:o}")
        if member.isreg():
            declared_total += member.size
            if declared_total > MAX_ARCHIVE_BYTES:
                fail("archive members exceed configured size limit")
    if len(roots) != 1:
        fail(f"archive must contain exactly one top-level directory, found {sorted(roots)}")
    root = next(iter(roots))
    match = ROOT_PATTERN.fullmatch(root)
    if match is None:
        fail(f"archive root {root!r} does not identify a version and architecture")
    verify_tar_termination(archive, members)
    return root, match.group(1), match.group(2), seen


def verify_tar_termination(archive, members):
    content_end = max(
        ((member.offset_data + member.size + 511) // 512) * 512
        for member in members
    )
    archive.fileobj.seek(0, os.SEEK_END)
    archive_size = archive.fileobj.tell()
    if archive_size % 512 != 0 or archive_size - content_end < 1024:
        fail("archive is truncated or lacks canonical end-of-archive blocks")
    archive.fileobj.seek(content_end)
    while True:
        block = archive.fileobj.read(1024 * 1024)
        if not block:
            break
        if any(block):
            fail("archive contains non-zero trailing data after its final member")


def parse_manifest(body, root, version, architecture):
    try:
        manifest = json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"manifest is not valid UTF-8 JSON: {error}")
    if not isinstance(manifest, dict) or set(manifest) != {"manifest_version", "release", "required_roles", "artifacts"}:
        fail("manifest has missing or unknown top-level fields")
    if manifest["manifest_version"] != MANIFEST_VERSION:
        fail("unsupported offline manifest version")
    release = manifest["release"]
    expected_release_keys = {"version", "architecture", "created_at", "source_commit", "archive_root"}
    if not isinstance(release, dict) or set(release) != expected_release_keys:
        fail("manifest release metadata is incomplete or contains unknown fields")
    if release["version"] != version or release["architecture"] != architecture or release["archive_root"] != root:
        fail("manifest release identity does not match archive root")
    if not isinstance(release["created_at"], str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", release["created_at"]
    ):
        fail("manifest created_at must be UTC RFC3339 seconds")
    if not isinstance(release["source_commit"], str) or not re.fullmatch(
        r"(?:[0-9a-f]{40}|unknown)", release["source_commit"]
    ):
        fail("manifest source_commit is invalid")
    required_roles = manifest["required_roles"]
    if (
        not isinstance(required_roles, list)
        or not all(isinstance(role, str) for role in required_roles)
        or set(required_roles) != REQUIRED_ROLES
        or len(required_roles) != len(REQUIRED_ROLES)
    ):
        fail("manifest required_roles does not match the offline contract")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail("manifest artifacts must be a non-empty list")
    parsed = {}
    roles = set()
    expected_keys = {"path", "role", "sha256", "size_bytes", "mode"}
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or set(artifact) != expected_keys:
            fail(f"artifact {index} has missing or unknown fields")
        path = safe_payload_path(artifact["path"]).as_posix()
        if path in ("manifest.json", "SHA256SUMS") or path in parsed:
            fail(f"artifact path {path!r} is reserved or duplicated")
        role = artifact["role"]
        if not isinstance(role, str) or role not in ALLOWED_ROLES:
            fail(f"artifact {path!r} has unsupported role {role!r}")
        if not isinstance(artifact["sha256"], str) or not SHA256_PATTERN.fullmatch(artifact["sha256"]):
            fail(f"artifact {path!r} has invalid sha256")
        if not isinstance(artifact["size_bytes"], int) or isinstance(artifact["size_bytes"], bool) or artifact["size_bytes"] < 0:
            fail(f"artifact {path!r} has invalid size")
        if artifact["mode"] not in ("0644", "0755"):
            fail(f"artifact {path!r} has invalid mode")
        parsed[path] = artifact
        roles.add(role)
    missing_roles = sorted(REQUIRED_ROLES - roles)
    if missing_roles:
        fail(f"manifest is missing required artifact roles: {missing_roles}")
    required_paths = {
        f"images/ulpf-{architecture}.tar": "image.ulpf",
        f"images/clickhouse-{architecture}.tar": "image.clickhouse",
        "compose/compose.yaml": "compose",
        "config/ulpf.yaml": "config",
        "migrations/clickhouse/001_events.sql": "migration.clickhouse",
        "licenses/LICENSE": "license",
        "licenses/OCSF-LICENSE": "license",
        "install/verify-offline-bundle.py": "verifier",
    }
    for path, role in required_paths.items():
        if path not in parsed or parsed[path]["role"] != role:
            fail(f"manifest is missing required {role!r} artifact at {path!r}")
    for role in ("image.ulpf", "image.clickhouse", "compose", "config", "migration.clickhouse", "verifier"):
        if sum(item["role"] == role for item in parsed.values()) != 1:
            fail(f"manifest must contain exactly one {role!r} artifact")
    if parsed["install/verify-offline-bundle.py"]["mode"] != "0755":
        fail("bundled verifier must be executable")
    if not any(path.startswith("docs/") and item["role"] == "documentation" for path, item in parsed.items()):
        fail("manifest does not contain documentation below docs/")
    if not any(path.startswith("schemas/") and item["role"] == "schema" for path, item in parsed.items()):
        fail("manifest does not contain schemas below schemas/")
    constrained_prefixes = {
        "documentation": "docs/",
        "schema": "schemas/",
        "license": "licenses/",
    }
    for path, artifact in parsed.items():
        prefix = constrained_prefixes.get(artifact["role"])
        if prefix is not None and not path.startswith(prefix):
            fail(f"artifact {path!r} must be stored below {prefix!r} for role {artifact['role']!r}")
    return manifest, parsed


def parse_checksums(body):
    try:
        lines = body.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("SHA256SUMS is not ASCII")
    if not lines:
        fail("SHA256SUMS must be non-empty")
    checksums = {}
    ordered_paths = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            fail(f"malformed checksum line {line!r}")
        path = safe_payload_path(match.group(2)).as_posix()
        if path == "SHA256SUMS" or path in checksums:
            fail(f"checksum path {path!r} is reserved or duplicated")
        checksums[path] = match.group(1)
        ordered_paths.append(path)
    if ordered_paths != sorted(ordered_paths):
        fail("SHA256SUMS paths must be sorted")
    return checksums


def verify_payload(archive, root, members, artifacts, checksums, version, architecture):
    regular = {
        PurePosixPath(name).relative_to(root).as_posix(): member
        for name, member in members.items()
        if member.isreg()
    }
    expected_regular = set(artifacts) | {"manifest.json", "SHA256SUMS"}
    if set(regular) != expected_regular:
        fail(
            "archive/manifest coverage mismatch: "
            f"missing={sorted(expected_regular - set(regular))} undeclared={sorted(set(regular) - expected_regular)}"
        )
    expected_directories = {root}
    for relative in expected_regular:
        full_path = PurePosixPath(root) / relative
        expected_directories.update(parent.as_posix() for parent in full_path.parents if parent.as_posix() != ".")
    actual_directories = {name for name, member in members.items() if member.isdir()}
    if actual_directories != expected_directories:
        fail(
            "archive directory coverage mismatch: "
            f"missing={sorted(expected_directories - actual_directories)} "
            f"undeclared={sorted(actual_directories - expected_directories)}"
        )
    expected_checksums = set(artifacts) | {"manifest.json"}
    if set(checksums) != expected_checksums:
        fail("SHA256SUMS coverage does not match the manifest")
    image_tags = {}
    for relative in sorted(expected_checksums):
        member = regular[relative]
        stream = archive.extractfile(member)
        if stream is None:
            fail(f"cannot read {relative!r}")
        digest, size = digest_stream(stream, MAX_ARCHIVE_BYTES)
        if digest != checksums[relative]:
            fail(f"checksum mismatch for {relative!r}")
        if relative in artifacts:
            artifact = artifacts[relative]
            if digest != artifact["sha256"] or size != artifact["size_bytes"]:
                fail(f"manifest integrity metadata mismatch for {relative!r}")
            if member.mode != int(artifact["mode"], 8):
                fail(f"archive mode does not match manifest for {relative!r}")
            if artifact["role"].startswith("image."):
                role = artifact["role"][len("image."):]
                image_tags[role] = verify_image_archive(
                    archive, member, relative, architecture, role, version
                )
    compose_member = regular["compose/compose.yaml"]
    verify_release_compose(read_member(archive, compose_member, MAX_MANIFEST_BYTES), image_tags)


def valid_image_tag(role, tag, version):
    if not isinstance(tag, str) or not IMAGE_TAG_PATTERN.fullmatch(tag):
        fail(f"container image {role!r} has invalid Docker tag {tag!r}")
    repository, image_version = tag.rsplit(":", 1)
    repository_without_registry = repository.rsplit("/", 1)[-1]
    if role == "ulpf":
        if repository_without_registry != "ulpf" or image_version != version:
            fail(f"ulpf image must have the release tag ulpf:{version}, found {tag!r}")
    elif role == "clickhouse":
        if not repository.endswith("clickhouse/clickhouse-server") or image_version == "latest":
            fail("clickhouse image must use a versioned clickhouse/clickhouse-server tag")
    return tag


def verify_image_archive(archive, member, relative, architecture, role, version):
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read container image archive {relative!r}")
    members = {}
    bodies = {}
    digests = {}
    declared_total = 0
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as image_archive:
            for index, nested in enumerate(image_archive):
                if index >= MAX_MEMBERS:
                    fail(f"container image archive {relative!r} contains too many members")
                nested_path = safe_member_name(nested.name).as_posix()
                if nested_path in members:
                    fail(f"container image archive {relative!r} contains duplicate path {nested_path!r}")
                if not (nested.isdir() or nested.isreg()):
                    fail(f"container image archive {relative!r} contains a link or special file")
                members[nested_path] = nested
                if nested.isreg():
                    declared_total += nested.size
                    if declared_total > MAX_ARCHIVE_BYTES:
                        fail(f"container image archive {relative!r} exceeds the configured size limit")
                    nested_stream = image_archive.extractfile(nested)
                    if nested_stream is None:
                        fail(f"cannot read container image member {nested_path!r}")
                    digest = hashlib.sha256()
                    body = bytearray() if nested_path == "manifest.json" or nested_path.endswith(".json") else None
                    while True:
                        chunk = nested_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        if body is not None:
                            if len(body) + len(chunk) > MAX_IMAGE_JSON_BYTES:
                                fail(f"container image JSON member {nested_path!r} is too large")
                            body.extend(chunk)
                    digests[nested_path] = digest.hexdigest()
                    if body is not None:
                        bodies[nested_path] = bytes(body)
    except tarfile.TarError as error:
        fail(f"container image artifact {relative!r} is not a tar archive: {error}")
    manifest_body = bodies.get("manifest.json")
    if manifest_body is None:
        fail(f"container image archive {relative!r} is not a Docker-save archive")
    manifest = decode_json(manifest_body, f"container image {role!r} manifest.json")
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        fail(f"container image {role!r} must contain exactly one manifest entry")
    entry = manifest[0]
    if set(entry) != {"Config", "RepoTags", "Layers"}:
        fail(f"container image {role!r} manifest entry has missing or unknown fields")
    config_name, tags, layers = entry["Config"], entry["RepoTags"], entry["Layers"]
    if not isinstance(config_name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", config_name):
        fail(f"container image {role!r} has an invalid content-addressed config path")
    if not isinstance(tags, list) or len(tags) != 1:
        fail(f"container image {role!r} must contain exactly one repository tag")
    tag = valid_image_tag(role, tags[0], version)
    if not isinstance(layers, list) or not layers or not all(isinstance(item, str) for item in layers) or len(set(layers)) != len(layers):
        fail(f"container image {role!r} has an invalid or duplicate layer list")
    config_body = bodies.get(config_name)
    if config_body is None or config_name not in members or not members[config_name].isreg():
        fail(f"container image {role!r} config is missing")
    if hashlib.sha256(config_body).hexdigest() != config_name[:-5]:
        fail(f"container image {role!r} config digest does not match its filename")
    config = decode_json(config_body, f"container image {role!r} config")
    if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != architecture:
        fail(f"container image {role!r} config must target linux/{architecture}")
    rootfs = config.get("rootfs")
    diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) and rootfs.get("type") == "layers" else None
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layers) or not all(isinstance(item, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in diff_ids):
        fail(f"container image {role!r} rootfs diff_ids must match the layer count")
    for index, layer_name in enumerate(layers):
        canonical = safe_member_name(layer_name).as_posix()
        layer = members.get(canonical)
        actual = digests.get(canonical)
        if layer is None or not layer.isreg() or actual is None:
            fail(f"container image {role!r} referenced layer {canonical!r} is missing")
        if canonical.endswith("/layer.tar") and diff_ids[index] != "sha256:" + actual:
            fail(f"container image {role!r} layer {canonical!r} does not match rootfs diff_id")
        blob_match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", canonical)
        if blob_match is not None and blob_match.group(1) != actual:
            fail(f"container image {role!r} blob {canonical!r} does not match its content digest")
    return tag


def verify_release_compose(body, image_tags):
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        fail("offline Compose file is not UTF-8")
    if "__ULPF_IMAGE__" in text or "__CLICKHOUSE_IMAGE__" in text:
        fail("offline Compose still contains an unrendered image marker")
    if re.search(r"(?m)^\s*build\s*:", text):
        fail("offline Compose must not contain a build directive")
    references = re.findall(r"(?m)^\s*image\s*:\s*([^\s#]+)\s*$", text)
    expected = [image_tags["ulpf"], image_tags["clickhouse"]]
    if sorted(references) != sorted(expected) or len(references) != len(expected):
        fail("offline Compose image references do not match the packaged image tags")
    if len(re.findall(r"(?m)^\s*pull_policy\s*:\s*never\s*$", text)) != len(expected):
        fail("offline Compose must set pull_policy: never for every image service")
    migration_mount = "../migrations/clickhouse/001_events.sql:/docker-entrypoint-initdb.d/001_events.sql:ro"
    if migration_mount not in text:
        fail("offline Compose does not mount the packaged ClickHouse migration")


def extract_verified(archive, root, members, artifacts, checksums, destination):
    if destination.exists() or destination.is_symlink():
        fail(f"extraction destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.extract-", dir=str(destination.parent)))
    completed = False
    try:
        for name, member in sorted(members.items()):
            relative = PurePosixPath(name).relative_to(root)
            target = temporary.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                fail(f"cannot extract {relative.as_posix()!r}")
            with target.open("xb") as output:
                digest, size = digest_stream(source, MAX_ARCHIVE_BYTES, output)
            payload_path = relative.as_posix()
            if payload_path == "SHA256SUMS":
                expected_digest = hashlib.sha256(read_member(archive, member)).hexdigest()
            else:
                expected_digest = checksums[payload_path]
            if digest != expected_digest or size != member.size:
                fail(f"content changed while extracting {payload_path!r}")
            os.chmod(target, member.mode)
        os.replace(temporary, destination)
        completed = True
    finally:
        if not completed:
            shutil.rmtree(temporary, ignore_errors=True)


def verify_archive(archive_path, extract_to=None, test_mode=False):
    if archive_path.is_symlink() or not archive_path.is_file():
        fail("archive must be a regular, non-symlink file")
    sidecar_verified = verify_sidecar(archive_path)
    if not sidecar_verified and not test_mode:
        fail("archive checksum sidecar is required; --test-mode is only for repository fixtures")
    with tempfile.TemporaryDirectory(prefix="ulpf-offline-verify-") as temporary:
        tar_path = materialize_tar(archive_path, temporary)
        try:
            archive = tarfile.open(tar_path, "r:")
        except tarfile.TarError as error:
            fail(f"archive is not a valid uncompressed tar stream: {error}")
        with archive:
            root, version, architecture, members = inventory_archive(archive)
            manifest_name = f"{root}/manifest.json"
            checksums_name = f"{root}/SHA256SUMS"
            if manifest_name not in members or not members[manifest_name].isreg():
                fail("archive does not contain a regular manifest.json")
            if checksums_name not in members or not members[checksums_name].isreg():
                fail("archive does not contain a regular SHA256SUMS")
            manifest_body = read_member(archive, members[manifest_name], MAX_MANIFEST_BYTES)
            _, artifacts = parse_manifest(manifest_body, root, version, architecture)
            checksums = parse_checksums(read_member(archive, members[checksums_name], MAX_MANIFEST_BYTES))
            verify_payload(archive, root, members, artifacts, checksums, version, architecture)
            if extract_to is not None:
                extract_verified(archive, root, members, artifacts, checksums, extract_to)
    print(
        f"offline bundle verified: version={version} architecture={architecture} "
        f"artifacts={len(artifacts)} sidecar={'yes' if sidecar_verified else 'no'}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--extract", metavar="DIRECTORY")
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="allow a missing outer checksum sidecar for repository fixtures only",
    )
    args = parser.parse_args()
    try:
        archive = Path(os.path.abspath(os.path.expanduser(args.archive)))
        extract_to = Path(os.path.abspath(os.path.expanduser(args.extract))) if args.extract else None
        verify_archive(archive, extract_to, args.test_mode)
    except (VerificationError, OSError, tarfile.TarError) as error:
        print(f"offline bundle verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
