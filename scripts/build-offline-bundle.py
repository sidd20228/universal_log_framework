#!/usr/bin/env python3
"""Assemble a deterministic ULPF offline release archive from fixed inputs."""

import argparse
import datetime as dt
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


MANIFEST_VERSION = "ulpf-offline-bundle/1.2.0"
REQUIRED_IMAGES = ("ulpf", "clickhouse")
OPTIONAL_ROLES = {"sbom", "vulnerability_report", "license_inventory", "notice"}
REQUIRED_RELEASE_ROLES = {"sbom", "vulnerability_report", "license_inventory"}
VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$")
COMMIT_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|unknown)$")
IMAGE_TAG_PATTERN = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$")
MAX_IMAGE_JSON_BYTES = 4 * 1024 * 1024
COMPOSE_MARKERS = {"ulpf": "__ULPF_IMAGE__", "clickhouse": "__CLICKHOUSE_IMAGE__"}


def fail(message):
    raise SystemExit(f"offline bundle build: {message}")


def parse_mapping(value, option):
    if "=" not in value:
        fail(f"{option} requires NAME=VALUE")
    name, mapped = value.split("=", 1)
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) or not mapped:
        fail(f"invalid {option} value {value!r}")
    return name, mapped


def parse_artifact(value):
    if "=" not in value or ":" not in value.split("=", 1)[0]:
        fail("--artifact requires ROLE:DESTINATION=FILE")
    identity, source = value.split("=", 1)
    role, destination = identity.split(":", 1)
    if role not in OPTIONAL_ROLES or not destination or not source:
        fail(f"invalid --artifact value {value!r}")
    return role, destination, source


def reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail(f"container image JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def decode_json(body, label):
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")


def safe_image_member(name, label):
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        fail(f"{label} contains unsafe member {name!r}")
    stripped = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(stripped)
    if not path.parts or any(part in ("", ".", "..") for part in path.parts) or path.as_posix() != stripped:
        fail(f"{label} contains non-canonical member {name!r}")
    return path.as_posix()


def validate_image_tag(role, tag, version):
    if not isinstance(tag, str) or not IMAGE_TAG_PATTERN.fullmatch(tag):
        fail(f"{role} image has invalid Docker tag {tag!r}")
    repository, image_version = tag.rsplit(":", 1)
    repository_without_registry = repository.rsplit("/", 1)[-1]
    if role == "ulpf":
        if repository_without_registry != "ulpf" or image_version != version:
            fail(f"ulpf image must have the release tag ulpf:{version}, found {tag!r}")
    elif role == "clickhouse":
        if not repository.endswith("clickhouse/clickhouse-server") or image_version == "latest":
            fail("clickhouse image must use a versioned clickhouse/clickhouse-server tag")
    return tag


def validate_layer_sources(value, diff_ids, label):
    if value is None:
        return
    if not isinstance(value, dict):
        fail(f"{label} LayerSources must be an object")
    allowed = {"mediaType", "digest", "size", "urls", "annotations", "platform"}
    for diff_id, descriptor in value.items():
        if diff_id not in diff_ids:
            fail(f"{label} LayerSources key does not match a rootfs diff_id")
        if not isinstance(descriptor, dict) or not {"mediaType", "digest", "size"}.issubset(descriptor) or not set(descriptor).issubset(allowed):
            fail(f"{label} LayerSources descriptor is incomplete or contains unknown fields")
        if not isinstance(descriptor["mediaType"], str) or not descriptor["mediaType"]:
            fail(f"{label} LayerSources media type is invalid")
        if not isinstance(descriptor["digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor["digest"]):
            fail(f"{label} LayerSources digest is invalid")
        if type(descriptor["size"]) is not int or descriptor["size"] < 0:
            fail(f"{label} LayerSources size is invalid")
        if descriptor.get("urls") not in (None, []):
            fail(f"{label} uses external layer URLs, which are forbidden in an offline release")
        annotations = descriptor.get("annotations")
        if annotations is not None and (not isinstance(annotations, dict) or not all(isinstance(key, str) and isinstance(item, str) for key, item in annotations.items())):
            fail(f"{label} LayerSources annotations are invalid")
        if descriptor.get("platform") is not None and not isinstance(descriptor["platform"], dict):
            fail(f"{label} LayerSources platform is invalid")


def inspect_docker_image(path, architecture, role, version):
    source = regular_source(path, f"image.{role}")
    try:
        archive = tarfile.open(source, "r:*")
    except tarfile.TarError as error:
        fail(f"image.{role} is not a Docker-save tar archive: {error}")
    with archive:
        members = {}
        for member in archive.getmembers():
            name = safe_image_member(member.name, f"image.{role}")
            if name in members:
                fail(f"image.{role} contains duplicate member {name!r}")
            if not (member.isdir() or member.isreg()):
                fail(f"image.{role} contains a link or special member {name!r}")
            members[name] = member
        manifest_member = members.get("manifest.json")
        if manifest_member is None or not manifest_member.isreg() or manifest_member.size > MAX_IMAGE_JSON_BYTES:
            fail(f"image.{role} must contain a bounded regular manifest.json")
        manifest = decode_json(archive.extractfile(manifest_member).read(), f"image.{role} manifest.json")
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            fail(f"image.{role} must contain exactly one Docker-save manifest entry")
        entry = manifest[0]
        required_fields = {"Config", "RepoTags", "Layers"}
        allowed_fields = required_fields | {"Parent", "LayerSources"}
        if not required_fields.issubset(entry) or not set(entry).issubset(allowed_fields):
            fail(f"image.{role} manifest entry has missing or unknown fields: {sorted(entry)}")
        parent = entry.get("Parent")
        if parent is not None and (not isinstance(parent, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", parent)):
            fail(f"image.{role} manifest parent is invalid")
        layer_sources = entry.get("LayerSources")
        config_name, tags, layers = entry["Config"], entry["RepoTags"], entry["Layers"]
        legacy_config = re.fullmatch(r"([0-9a-f]{64})\.json", config_name) if isinstance(config_name, str) else None
        oci_config = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", config_name) if isinstance(config_name, str) else None
        if legacy_config is None and oci_config is None:
            fail(f"image.{role} has an invalid content-addressed config path")
        config_digest = (legacy_config or oci_config).group(1)
        if not isinstance(tags, list) or len(tags) != 1:
            fail(f"image.{role} must contain exactly one repository tag")
        tag = validate_image_tag(role, tags[0], version)
        if not isinstance(layers, list) or not layers or not all(isinstance(item, str) for item in layers) or len(set(layers)) != len(layers):
            fail(f"image.{role} has an invalid or duplicate layer list")
        config_member = members.get(config_name)
        if config_member is None or not config_member.isreg() or config_member.size > MAX_IMAGE_JSON_BYTES:
            fail(f"image.{role} config is missing or too large")
        config_body = archive.extractfile(config_member).read()
        if hashlib.sha256(config_body).hexdigest() != config_digest:
            fail(f"image.{role} config digest does not match its filename")
        config = decode_json(config_body, f"image.{role} config")
        if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != architecture:
            fail(f"image.{role} config must target linux/{architecture}")
        rootfs = config.get("rootfs")
        diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) and rootfs.get("type") == "layers" else None
        if not isinstance(diff_ids, list) or len(diff_ids) != len(layers) or not all(isinstance(item, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in diff_ids):
            fail(f"image.{role} rootfs diff_ids must match the layer count")
        validate_layer_sources(layer_sources, set(diff_ids), f"image.{role}")
        for index, layer_name in enumerate(layers):
            canonical = safe_image_member(layer_name, f"image.{role}")
            layer = members.get(canonical)
            if layer is None or not layer.isreg():
                fail(f"image.{role} referenced layer {canonical!r} is missing")
            stream = archive.extractfile(layer)
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            actual = digest.hexdigest()
            if canonical.endswith("/layer.tar") and diff_ids[index] != "sha256:" + actual:
                fail(f"image.{role} layer {canonical!r} does not match rootfs diff_id")
            blob_match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", canonical)
            if blob_match is not None and blob_match.group(1) != actual:
                fail(f"image.{role} blob {canonical!r} does not match its content digest")
        return tag


def render_compose(template_path, image_tags):
    source = regular_source(template_path, "compose template")
    if source.stat().st_size > 1024 * 1024:
        fail("compose template is unexpectedly large")
    try:
        body = source.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        fail("compose template is not UTF-8")
    for role, marker in COMPOSE_MARKERS.items():
        if body.count(marker) != 1:
            fail(f"compose template must contain marker {marker!r} exactly once")
        body = body.replace(marker, image_tags[role])
    if re.search(r"(?m)^\s*build\s*:", body):
        fail("offline compose must not contain a build directive")
    if len(re.findall(r"(?m)^\s*pull_policy\s*:\s*never\s*$", body)) != len(REQUIRED_IMAGES):
        fail("offline compose must set pull_policy: never for every image service")
    if "../migrations/clickhouse/001_events.sql:/docker-entrypoint-initdb.d/001_events.sql:ro" not in body:
        fail("offline compose must mount the packaged ClickHouse migration read-only")
    return body.encode("utf-8")


def regular_source(path, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        fail(f"{label} must be a regular, non-symlink file: {candidate}")
    return candidate.resolve()


def directory_source(path, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_dir():
        fail(f"{label} must be a real directory: {candidate}")
    return candidate.resolve()


def find_engine():
    for engine in ("docker", "podman"):
        executable = shutil.which(engine)
        if executable is None:
            continue
        result = subprocess.run(
            [executable, "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )
        if result.returncode == 0:
            return executable
    return None


def export_image(engine, reference, target):
    inspect = subprocess.run(
        [engine, "image", "inspect", reference],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if inspect.returncode != 0:
        fail(f"container image is not present locally: {reference}")
    command = [engine, "save", "--output", str(target), reference]
    if Path(engine).name == "podman":
        command = [engine, "save", "--format", "docker-archive", "--output", str(target), reference]
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        fail(f"failed to export container image {reference!r} with {Path(engine).name}")


def safe_relative(path):
    relative = PurePosixPath(path)
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        fail(f"unsafe destination path {path!r}")
    return relative


class Assembly:
    def __init__(self, root, epoch):
        self.root = root
        self.epoch = epoch
        self.artifacts = {}

    def add_file(self, source, destination, role, executable=False):
        source_path = regular_source(source, role)
        relative = safe_relative(destination)
        key = relative.as_posix()
        if key in ("manifest.json", "SHA256SUMS"):
            fail(f"destination path {key!r} is reserved")
        if key in self.artifacts:
            fail(f"duplicate destination path {key!r}")
        target = self.root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with source_path.open("rb") as reader, target.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
        mode = 0o755 if executable else 0o644
        os.chmod(target, mode)
        os.utime(target, (self.epoch, self.epoch), follow_symlinks=False)
        digest, size = digest_file(target)
        self.artifacts[key] = {
            "path": key,
            "role": role,
            "sha256": digest,
            "size_bytes": size,
            "mode": format(mode, "04o"),
        }

    def add_bytes(self, body, destination, role, executable=False):
        relative = safe_relative(destination)
        key = relative.as_posix()
        if key in ("manifest.json", "SHA256SUMS") or key in self.artifacts:
            fail(f"duplicate or reserved destination path {key!r}")
        target = self.root.joinpath(*relative.parts)
        mode = 0o755 if executable else 0o644
        write_bytes(target, body, mode, self.epoch)
        digest, size = digest_file(target)
        self.artifacts[key] = {
            "path": key,
            "role": role,
            "sha256": digest,
            "size_bytes": size,
            "mode": format(mode, "04o"),
        }

    def add_tree(self, source, destination, role):
        source_root = directory_source(source, role)
        files = []
        for current, directories, names in os.walk(source_root, followlinks=False):
            directories.sort()
            names.sort()
            current_path = Path(current)
            for directory in directories:
                candidate = current_path / directory
                if candidate.is_symlink():
                    fail(f"{role} tree contains a symlink: {candidate}")
            for name in names:
                candidate = current_path / name
                if candidate.is_symlink() or not candidate.is_file():
                    fail(f"{role} tree contains a non-regular file: {candidate}")
                files.append(candidate)
        if not files:
            fail(f"{role} tree must contain at least one file")
        for source_path in files:
            relative = source_path.relative_to(source_root).as_posix()
            self.add_file(source_path, f"{destination}/{relative}", role)


def digest_file(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def write_bytes(path, body, mode, epoch):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(body)
    os.chmod(path, mode)
    os.utime(path, (epoch, epoch), follow_symlinks=False)


def write_deterministic_tar(source_root, archive_root, target, epoch):
    with tarfile.open(target, "w", format=tarfile.GNU_FORMAT) as archive:
        directories = {PurePosixPath(archive_root)}
        files = []
        for path in sorted(source_root.rglob("*"), key=lambda item: item.relative_to(source_root).as_posix()):
            relative = PurePosixPath(archive_root) / PurePosixPath(path.relative_to(source_root).as_posix())
            if path.is_dir():
                directories.add(relative)
            else:
                files.append((path, relative))
                directories.update(parent for parent in relative.parents if parent.as_posix() != ".")
        for directory in sorted(directories, key=lambda item: (len(item.parts), item.as_posix())):
            info = tarfile.TarInfo(directory.as_posix() + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            archive.addfile(info)
        for path, relative in files:
            info = tarfile.TarInfo(relative.as_posix())
            info.size = path.stat().st_size
            info.mode = path.stat().st_mode & 0o777
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            with path.open("rb") as stream:
                archive.addfile(info, stream)


def compress_zstd(source, target):
    zstd = shutil.which("zstd")
    if zstd is None:
        fail("zstd is required to create .tar.zst output; use a .tar output for an uncompressed archive")
    result = subprocess.run(
        [zstd, "-q", "-19", "-T1", "-f", str(source), "-o", str(target)],
        check=False,
    )
    if result.returncode != 0:
        fail("zstd compression failed")


def public_key_id(public_key):
    openssl = shutil.which("openssl")
    if openssl is None:
        fail("openssl is required to sign a release bundle")
    result = subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0 or not result.stdout:
        fail("signing public key is not a valid PEM public key")
    return "sha256:" + hashlib.sha256(result.stdout).hexdigest()


def write_signature(archive, digest, private_key, public_key, signed_at, expires_at, epoch):
    openssl = shutil.which("openssl")
    if openssl is None:
        fail("openssl is required to sign a release bundle")
    statement_path = Path(str(archive) + ".signature.json")
    signature_path = Path(str(archive) + ".signature.sig")
    for path in (statement_path, signature_path):
        if path.exists() or path.is_symlink():
            fail(f"signature output already exists: {path}")
    statement = {
        "algorithm": "rsa-pkcs1v15-sha256",
        "archive_name": archive.name,
        "archive_sha256": digest,
        "expires_at": expires_at,
        "key_id": public_key_id(public_key),
        "schema_version": "ulpf-offline-signature/1",
        "signed_at": signed_at,
    }
    body = (json.dumps(statement, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    statement_path.write_bytes(body)
    result = subprocess.run(
        [openssl, "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_path), str(statement_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        statement_path.unlink(missing_ok=True)
        signature_path.unlink(missing_ok=True)
        fail("failed to create detached release signature")
    for path in (statement_path, signature_path):
        os.chmod(path, 0o644)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    return statement_path, signature_path


def parse_arguments():
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--source-commit", default="unknown")
    parser.add_argument("--source-date-epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    parser.add_argument("--output", required=True)
    parser.add_argument("--compose", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--clickhouse-migration",
        default=str(script_root / "migrations/clickhouse/001_events.sql"),
    )
    parser.add_argument("--image", action="append", default=[], metavar="NAME=ARCHIVE")
    parser.add_argument("--image-ref", action="append", default=[], metavar="NAME=REFERENCE")
    parser.add_argument(
        "--artifact", action="append", default=[], metavar="ROLE:DESTINATION=FILE",
        help="add an sbom, vulnerability_report, license_inventory, or notice artifact",
    )
    parser.add_argument("--signing-key", help="PEM RSA private key used only for the detached release statement")
    parser.add_argument("--signing-public-key", help="separately distributed PEM public key matching --signing-key")
    parser.add_argument("--signature-expires-at", help="UTC RFC3339-seconds expiry for the detached signature")
    parser.add_argument(
        "--unsigned-test-bundle", action="store_true",
        help="omit publisher signature only for repository fixtures; never use for a release",
    )
    parser.add_argument("--docs-root", default=str(script_root / "docs"))
    parser.add_argument("--schemas-root", default=str(script_root / "schemas"))
    parser.add_argument("--license", default=str(script_root / "LICENSE"))
    parser.add_argument("--ocsf-license", default=str(script_root / "schemas/vendor/ocsf/1.9.0/LICENSE"))
    parser.add_argument("--verifier", default=str(script_root / "scripts/verify-offline-bundle.py"))
    return parser.parse_args()


def main():
    args = parse_arguments()
    if not VERSION_PATTERN.fullmatch(args.version):
        fail("version contains unsupported characters")
    if not COMMIT_PATTERN.fullmatch(args.source_commit):
        fail("source commit must be 40 lowercase hexadecimal characters or 'unknown'")
    if args.source_date_epoch < 0:
        fail("source date epoch cannot be negative")
    signed_at = dt.datetime.fromtimestamp(args.source_date_epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signing_values = (args.signing_key, args.signing_public_key, args.signature_expires_at)
    if args.unsigned_test_bundle:
        if any(signing_values):
            fail("--unsigned-test-bundle cannot be combined with signing options")
    elif not all(signing_values):
        fail("release bundles require --signing-key, --signing-public-key, and --signature-expires-at")
    if args.signature_expires_at:
        try:
            expires = dt.datetime.strptime(args.signature_expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            fail("--signature-expires-at must use UTC RFC3339 seconds")
        if expires <= dt.datetime.fromtimestamp(args.source_date_epoch, tz=dt.timezone.utc):
            fail("signature expiry must be later than the signing time")
    output = Path(os.path.abspath(os.path.expanduser(args.output)))
    if not (output.name.endswith(".tar") or output.name.endswith(".tar.zst")):
        fail("output must end in .tar or .tar.zst")
    output.parent.mkdir(parents=True, exist_ok=True)
    sidecar_path = Path(str(output) + ".sha256")
    signature_outputs = (Path(str(output) + ".signature.json"), Path(str(output) + ".signature.sig"))
    if output.exists() or output.is_symlink() or sidecar_path.exists() or sidecar_path.is_symlink() or any(path.exists() or path.is_symlink() for path in signature_outputs):
        fail(f"output already exists: {output}")

    images = {}
    for value in args.image:
        name, source = parse_mapping(value, "--image")
        if name in images:
            fail(f"duplicate image name {name!r}")
        images[name] = ("archive", source)
    for value in args.image_ref:
        name, reference = parse_mapping(value, "--image-ref")
        if name in images:
            fail(f"duplicate image name {name!r}")
        images[name] = ("reference", reference)
    missing_images = sorted(set(REQUIRED_IMAGES) - set(images))
    extra_images = sorted(set(images) - set(REQUIRED_IMAGES))
    if missing_images or extra_images:
        fail(f"image inventory mismatch: missing={missing_images} unexpected={extra_images}")

    archive_root = f"ulpf-offline-{args.version}-{args.arch}"
    created_at = dt.datetime.fromtimestamp(args.source_date_epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="ulpf-offline-build-") as temporary:
        temporary_root = Path(temporary)
        payload_root = temporary_root / "payload"
        payload_root.mkdir()
        assembly = Assembly(payload_root, args.source_date_epoch)
        assembly.add_file(args.config, "config/ulpf.yaml", "config")
        assembly.add_file(
            args.clickhouse_migration,
            "migrations/clickhouse/001_events.sql",
            "migration.clickhouse",
        )
        assembly.add_tree(args.docs_root, "docs", "documentation")
        assembly.add_tree(args.schemas_root, "schemas", "schema")
        assembly.add_file(args.license, "licenses/LICENSE", "license")
        assembly.add_file(args.ocsf_license, "licenses/OCSF-LICENSE", "license")
        assembly.add_file(args.verifier, "install/verify-offline-bundle.py", "verifier", executable=True)
        for value in args.artifact:
            role, destination, source = parse_artifact(value)
            assembly.add_file(source, destination, role)
        present_release_roles = {item["role"] for item in assembly.artifacts.values()}
        missing_release_roles = sorted(REQUIRED_RELEASE_ROLES - present_release_roles)
        if missing_release_roles:
            fail(f"release artifact inventory is missing required roles: {missing_release_roles}")

        engine = None
        image_tags = {}
        for name in REQUIRED_IMAGES:
            source_kind, source_value = images[name]
            source_path = source_value
            if source_kind == "reference":
                if engine is None:
                    engine = find_engine()
                if engine is None:
                    fail("--image-ref requires an available Docker or Podman engine")
                exported = temporary_root / f"{name}.tar"
                export_image(engine, source_value, exported)
                source_path = str(exported)
            image_tags[name] = inspect_docker_image(source_path, args.arch, name, args.version)
            assembly.add_file(source_path, f"images/{name}-{args.arch}.tar", f"image.{name}")

        assembly.add_bytes(render_compose(args.compose, image_tags), "compose/compose.yaml", "compose")

        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "release": {
                "version": args.version,
                "architecture": args.arch,
                "created_at": created_at,
                "source_commit": args.source_commit,
                "archive_root": archive_root,
            },
            "required_roles": [
                "image.ulpf", "image.clickhouse", "compose", "config", "migration.clickhouse",
                "documentation", "license", "schema", "verifier", "sbom",
                "vulnerability_report", "license_inventory",
            ],
            "artifacts": [assembly.artifacts[path] for path in sorted(assembly.artifacts)],
        }
        manifest_body = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_bytes(payload_root / "manifest.json", manifest_body, 0o644, args.source_date_epoch)

        checksum_paths = ["manifest.json"] + sorted(assembly.artifacts)
        checksum_lines = []
        for relative in sorted(checksum_paths):
            digest, _ = digest_file(payload_root / relative)
            checksum_lines.append(f"{digest}  {relative}\n")
        write_bytes(payload_root / "SHA256SUMS", "".join(checksum_lines).encode("ascii"), 0o644, args.source_date_epoch)

        tar_path = temporary_root / f"{archive_root}.tar"
        write_deterministic_tar(payload_root, archive_root, tar_path, args.source_date_epoch)
        if output.name.endswith(".tar.zst"):
            compress_zstd(tar_path, output)
        else:
            shutil.copyfile(tar_path, output)
        os.chmod(output, 0o644)
        os.utime(output, (args.source_date_epoch, args.source_date_epoch), follow_symlinks=False)
        archive_digest, _ = digest_file(output)
        sidecar = Path(str(output) + ".sha256")
        sidecar.write_text(f"{archive_digest}  {output.name}\n", encoding="ascii")
        os.chmod(sidecar, 0o644)
        os.utime(sidecar, (args.source_date_epoch, args.source_date_epoch), follow_symlinks=False)

        if not args.unsigned_test_bundle:
            statement_path, signature_path = write_signature(
                output, archive_digest, regular_source(args.signing_key, "signing private key"),
                regular_source(args.signing_public_key, "signing public key"), signed_at,
                args.signature_expires_at, args.source_date_epoch,
            )

        verifier = Path(__file__).resolve().with_name("verify-offline-bundle.py")
        verification_command = [sys.executable, str(verifier), str(output)]
        if args.unsigned_test_bundle:
            verification_command.append("--test-mode")
        else:
            verification_command.extend(["--trusted-public-key", args.signing_public_key])
        verified = subprocess.run(
            verification_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if verified.returncode != 0:
            output.unlink(missing_ok=True)
            sidecar.unlink(missing_ok=True)
            for path in signature_outputs:
                path.unlink(missing_ok=True)
            detail = verified.stderr.strip() or "verification failed without diagnostics"
            fail(f"assembled archive did not pass verification: {detail}")

    print(f"offline bundle created: {output}")
    print(f"sha256: {archive_digest}")


if __name__ == "__main__":
    main()
