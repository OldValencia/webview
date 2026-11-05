import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from package import TARGETS, architectures, package, verify


def pe(machine):
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    struct.pack_into("<H", data, 86, 0x2000)
    return bytes(data)


def elf(machine):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 3, machine)
    return bytes(data)


def universal():
    data = bytearray(112)
    data[:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">I", data, 4, 2)
    for i, machine in enumerate((0x1000007, 0x100000C)):
        offset = 48 + i * 32
        struct.pack_into(">IIIII", data, 8 + i * 20, machine, 0, offset, 32, 0)
        data[offset:offset + 4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<III", data, offset + 4, machine, 0, 6)
    return bytes(data)


class NativePackageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "binary"
        self.output = self.root / "bundle"

    def make_bundle(self):
        for target, (kind, expected, _) in TARGETS.items():
            if kind == "pe":
                data = pe({"x86": 0x14C, "x86_64": 0x8664, "aarch64": 0xAA64}[next(iter(expected))])
            elif kind == "elf":
                data = elf(62 if expected == {"x86_64"} else 183)
            else:
                data = universal()
            self.source.write_bytes(data)
            package(self.source, self.output, target, "commit-1")

    def check(self):
        with contextlib.redirect_stdout(io.StringIO()):
            verify(self.output, "commit-1")

    def test_distinguishes_windows_architectures(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x86_64"), (0xAA64, "aarch64")):
            self.assertEqual({arch}, architectures(pe(machine), "pe"))

    def test_checks_elf_and_universal_macho(self):
        self.assertEqual({"aarch64"}, architectures(elf(183), "elf"))
        self.assertEqual({"x86_64", "aarch64"}, architectures(universal(), "macho"))
        damaged = bytearray(universal())
        struct.pack_into(">I", damaged, 16, len(damaged) + 1)
        with self.assertRaises(ValueError):
            architectures(bytes(damaged), "macho")

    def test_rejects_wrong_architecture_before_copying(self):
        self.source.write_bytes(pe(0xAA64))
        with self.assertRaises(ValueError):
            package(self.source, self.output, "windows-x86", "commit-1")
        self.assertFalse(self.output.exists())

    def test_rejects_truncated_or_wrong_binary_format(self):
        for kind in ("pe", "elf", "macho"):
            for data in (b"", b"MZ", b"\x7fELF", b"not a library"):
                with self.subTest(kind=kind, data=data), self.assertRaises(ValueError):
                    architectures(data, kind)

    def test_complete_bundle_has_seven_resource_files_and_checksums(self):
        self.make_bundle()
        self.check()
        self.assertEqual(7, len((self.output / "SHA256SUMS").read_text().splitlines()))

    def test_rejects_incomplete_or_changed_bundle(self):
        self.make_bundle()
        manifest = self.output / "metadata/windows-x86.json"
        original = manifest.read_bytes()
        manifest.unlink()
        with self.assertRaises(ValueError):
            self.check()
        manifest.write_bytes(original)
        binary = self.output / "natives/x86/windows_nt/webview.dll"
        binary.write_bytes(pe(0x8664))
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_wrong_commit_or_unexpected_resource_paths(self):
        self.make_bundle()
        path = self.output / "metadata/windows-x86.json"
        original = path.read_text()
        metadata = json.loads(original)
        metadata["revision"] = "different-commit"
        path.write_text(json.dumps(metadata))
        with self.assertRaises(ValueError):
            self.check()
        metadata = json.loads(original)
        metadata["libraries"][0]["path"] = "../outside.dll"
        path.write_text(json.dumps(metadata))
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_accidental_overwrite_and_extra_files(self):
        self.make_bundle()
        self.source.write_bytes(pe(0x14C))
        with self.assertRaises(ValueError):
            package(self.source, self.output, "windows-x86", "commit-1")
        (self.output / "natives/unexpected.dll").write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
