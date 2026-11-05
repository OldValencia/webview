"""Validate and package the supported native resource set using only the stdlib."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct


TARGETS = {
    "windows-x86_64": ("pe", {"x86_64"}, ["x86_64/windows_nt/webview.dll"]),
    "windows-x86": ("pe", {"x86"}, ["x86/windows_nt/webview.dll"]),
    "windows-aarch64": ("pe", {"aarch64"}, ["aarch64/windows_nt/webview.dll"]),
    "macos-universal": ("macho", {"x86_64", "aarch64"}, [
        "x86_64/macos/libwebview.dylib", "aarch64/macos/libwebview.dylib"]),
    "linux-gnu-x86_64": ("elf", {"x86_64"}, ["x86_64/linux/gnu/libwebview.so"]),
    "linux-gnu-aarch64": ("elf", {"aarch64"}, ["aarch64/linux/gnu/libwebview.so"]),
}


def architectures(data, kind):
    """Read the actual architecture; never trust a directory or runner label."""
    try:
        if kind == "pe":
            if data[:2] != b"MZ":
                raise ValueError("Not a PE library")
            offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[offset:offset + 4] != b"PE\0\0":
                raise ValueError("Invalid PE signature")
            machine = struct.unpack_from("<H", data, offset + 4)[0]
            flags = struct.unpack_from("<H", data, offset + 22)[0]
            if not (flags & 0x2000):
                raise ValueError("PE file is not a DLL")
            machines = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "aarch64"}
            return {machines[machine]}
        if kind == "elf":
            if data[:4] != b"\x7fELF" or data[5] not in (1, 2):
                raise ValueError("Not a supported ELF library")
            order = "<" if data[5] == 1 else ">"
            file_type, machine = struct.unpack_from(order + "HH", data, 16)
            if file_type != 3:
                raise ValueError("ELF file is not a shared object")
            arch = {3: "x86", 62: "x86_64", 183: "aarch64"}[machine]
            if data[4] != (1 if arch == "x86" else 2):
                raise ValueError("ELF class disagrees with its machine")
            return {arch}
        if kind == "macho":
            if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
                order = "<" if data[0] == 0xCF else ">"
                machine, _, file_type = struct.unpack_from(order + "III", data, 4)
                if file_type != 6:
                    raise ValueError("Mach-O file is not a dylib")
                machines = {0x1000007: "x86_64", 0x100000C: "aarch64"}
                return {machines[machine]}
            if data[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
                raise ValueError("Not a supported Mach-O library")
            count = struct.unpack_from(">I", data, 4)[0]
            wide = data[3] == 0xBF
            size = 32 if wide else 20
            if not 1 <= count <= 8 or len(data) < 8 + count * size:
                raise ValueError("Invalid universal Mach-O header")
            result = set()
            for i in range(count):
                entry = 8 + i * size
                machine = struct.unpack_from(">I", data, entry)[0]
                offset, length = struct.unpack_from(">QQ" if wide else ">II", data, entry + 8)
                if offset < 8 + count * size or offset + length > len(data):
                    raise ValueError("Invalid universal Mach-O slice")
                arch = {0x1000007: "x86_64", 0x100000C: "aarch64"}[machine]
                if arch in result or architectures(data[offset:offset + length], "macho") != {arch}:
                    raise ValueError("Invalid or duplicate universal Mach-O architecture")
                result.add(arch)
            return result
        raise ValueError("Unsupported binary format")
    except (IndexError, KeyError, struct.error) as failure:
        raise ValueError("Truncated binary or unsupported architecture") from failure


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package(source, output, target, revision):
    kind, expected, paths = TARGETS[target]
    data = source.read_bytes()
    found = architectures(data, kind)
    if found != expected:
        raise ValueError(f"{target} requires {sorted(expected)}, found {sorted(found)}")
    metadata = {"target": target, "revision": revision, "libraries": []}
    for relative in paths:
        relative = "natives/" + relative
        destination = output / relative
        if destination.exists():
            raise ValueError(f"Refusing to replace existing artifact: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        metadata["libraries"].append({"path": relative, "sha256": digest(data)})
    manifest = output / "metadata" / (target + ".json")
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def verify(root, revision):
    manifests = sorted((root / "metadata").glob("*.json"))
    if {p.stem for p in manifests} != set(TARGETS):
        raise ValueError("The bundle must contain metadata for every supported target")
    checksums = {}
    for manifest in manifests:
        metadata = json.loads(manifest.read_text(encoding="utf-8"))
        if metadata["target"] != manifest.stem or metadata["revision"] != revision:
            raise ValueError("Bundle metadata identifies a different target or commit")
        kind, expected, paths = TARGETS[manifest.stem]
        expected_paths = {"natives/" + p for p in paths}
        libraries = metadata["libraries"]
        if len(libraries) != len(paths) or {p["path"] for p in libraries} != expected_paths:
            raise ValueError("Missing, duplicate or unexpected library paths")
        for library in libraries:
            relative = library["path"]
            data = (root / relative).read_bytes()
            if digest(data) != library["sha256"] or architectures(data, kind) != expected:
                raise ValueError(f"Binary checksum or architecture mismatch: {relative}")
            if relative in checksums:
                raise ValueError(f"Duplicate resource path: {relative}")
            checksums[relative] = library["sha256"]
    actual = {p.relative_to(root).as_posix() for p in (root / "natives").rglob("*") if p.is_file()}
    if actual != set(checksums):
        raise ValueError("Unexpected or missing binaries in final bundle")
    (root / "SHA256SUMS").write_text("".join(
        f"{checksum}  {name}\n" for name, checksum in sorted(checksums.items())), encoding="utf-8")
    print(f"Verified {len(checksums)} libraries for {len(TARGETS)} targets at {revision}")


def smoke(source):
    library = ctypes.CDLL(str(source.resolve()))
    names = ("create", "destroy", "run", "terminate", "dispatch", "get_window",
             "get_native_handle", "set_title", "set_size", "navigate", "set_html",
             "init", "eval", "bind", "unbind", "return", "version")
    for name in names:
        getattr(library, "webview_" + name)
    class Version(ctypes.Structure):
        _fields_ = [("major", ctypes.c_uint), ("minor", ctypes.c_uint), ("patch", ctypes.c_uint)]
    library.webview_version.restype = ctypes.POINTER(Version)
    pointer = library.webview_version()
    if not pointer:
        raise ValueError("webview_version returned NULL")
    version = pointer.contents
    if (version.major, version.minor, version.patch) != (0, 12, 0):
        raise ValueError("Unexpected C API version; review bindings before publishing")
    print("Loaded library; C API exports and version 0.12.0 verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--source", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--target", choices=TARGETS, required=True)
    stage.add_argument("--revision", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--revision", required=True)
    load = commands.add_parser("smoke")
    load.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "stage":
        package(args.source, args.output, args.target, args.revision)
    elif args.command == "verify":
        verify(args.root, args.revision)
    else:
        smoke(args.source)


if __name__ == "__main__":
    main()
