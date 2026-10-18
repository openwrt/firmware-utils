#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Format, checksum and failure-path tests; no target or flash access.

python3 tests/test_y3_image.py build/y3-image
Add --vendor FILE.y3 for each optional legacy vendor image to repack.
"""

import argparse
import hashlib
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile
import unittest


class Y3ImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test-y3-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.input = self.directory / "input.ubi"
        self.output = self.directory / "output.y3"
        # Deliberately opaque after the EC header: the packager must not
        # interpret or change filesystems, volumes or their checksums.
        self.payload = b"UBI#\x01" + bytes(59) + bytes(range(256)) * 513
        self.input.write_bytes(self.payload)
        self.base = [str(BINARY), "-i", str(self.input), "-o", str(self.output),
                     "-c", "6846", "-m", "PANTHER", "-a", "all arm_xscale"]

    def run_tool(self, *args, success=True, command=None, **kwargs):
        result = subprocess.run((command or self.base) + list(args),
                                capture_output=True, timeout=30, **kwargs)
        self.assertNotIn(b"Sanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        self.assertEqual(result.returncode, 0 if success else 1,
                         result.stderr.decode(errors="replace"))
        return result

    def check_image(self, payload):
        image = self.output.read_bytes()
        header = image[:1024]
        text, padding = header.split(b"\0", 1)
        self.assertEqual(padding, bytes(len(padding)))
        lines = text.decode("ascii").splitlines()
        self.assertEqual(lines.pop(0), "IntenoIopY")
        fields = dict(line.split(" ", 1) for line in lines)
        self.assertEqual(len(fields), len(lines), "duplicate header keys")
        self.assertEqual(fields["version"], "8")
        self.assertEqual(fields["integrity"], "MD5SUM")
        self.assertEqual(fields["flags"], "singlepureubi bpartit32")
        self.assertEqual(int(fields["size"]), len(image))
        self.assertEqual(int(fields["md5ofs"]), len(image) - 32)
        self.assertEqual(fields["md5"], "32")
        self.assertEqual(image[-32:], hashlib.md5(image[:-32]).hexdigest().encode())
        self.assertEqual(int(fields["ubiofs"]), 1024)
        self.assertEqual(int(fields["ubi"]), len(payload))
        self.assertEqual(image[1024:-32], payload)
        for section in ("cfe", "rescue", "vmlinux", "ubifs", "pkginfo", "scr", "sig"):
            self.assertEqual(fields[section], "0", section)
            self.assertGreaterEqual(int(fields[section + "ofs"]), 1024)
            self.assertLessEqual(int(fields[section + "ofs"]), len(image) - 32)
        self.assertNotIn("loader", fields)
        self.assertNotIn("cfever", fields)
        # CFE's bounded scanner searches for newline-prefixed tags.
        for key in ("version", "chip", "cfeofs", "cfe", "vmlinuxofs",
                    "ubiofs", "ubi", "md5ofs", "size"):
            self.assertLess(header.index(b"\n" + key.encode() + b" "), 1005)
        return fields

    def test_help_and_required_options(self):
        self.run_tool("-h", command=[str(BINARY)])
        for args in ([], ["-i", str(self.input)], ["-z"]):
            self.run_tool(*args, command=[str(BINARY)], success=False)
        self.run_tool("extra", success=False)
        self.assertFalse(self.output.exists())

    def test_header_payload_and_checksum(self):
        self.run_tool()
        fields = self.check_image(self.payload)
        self.assertEqual(fields["chip"], "6846")
        self.assertEqual(fields["model"], "PANTHER")
        self.assertEqual(fields["arch"], "all arm_xscale")
        self.assertEqual(fields["release"], "OpenWrt")
        self.assertEqual(fields["customer"], "OpenWrt")
        self.assertEqual(fields["git"], "unknown")

    def test_other_router_metadata(self):
        self.run_tool("-c", "63138", "-m", "OTHER", "-a", "arm_cortex-a9",
                      "-r", "OpenWrt-test", "-u", "GNX", "-g", "0123456789")
        fields = self.check_image(self.payload)
        for key, value in dict(chip="63138", model="OTHER", arch="arm_cortex-a9",
                               release="OpenWrt-test", customer="GNX",
                               git="0123456789").items():
            self.assertEqual(fields[key], value)

    def test_deterministic(self):
        self.run_tool()
        first = self.output.read_bytes()
        self.run_tool(env=dict(os.environ, TZ="Pacific/Honolulu"))
        self.assertEqual(first, self.output.read_bytes())

    def test_copy_boundaries(self):
        for size in (64, 65535, 65536, 65537, 131072):
            with self.subTest(size=size):
                payload = self.payload[:size]
                self.input.write_bytes(payload)
                self.run_tool()
                self.check_image(payload)

    def test_size_limit_includes_header_and_checksum(self):
        size = len(self.payload) + 1056
        for limit in (str(size), hex(size), "0" + str(size)):
            self.run_tool("-s", limit)
            self.check_image(self.payload)
        saved = self.output.read_bytes()
        self.run_tool("-s", str(size - 1), success=False)
        self.assertEqual(saved, self.output.read_bytes())

    def test_sparse_oversized_input(self):
        for size in (0x03a20000, 2**32 + 64):
            with self.input.open("r+b") as stream:
                stream.truncate(size)
            self.run_tool(success=False)
        self.assertFalse(self.output.exists())

    def test_invalid_limits(self):
        for limit in ("", "0", "1119", "-1", "+4096", " 4096", "0x",
                      "0x1000junk", "2147483648", "18446744073709551616"):
            with self.subTest(limit=limit):
                self.run_tool("-s", limit, success=False)

    def test_invalid_chip_ids(self):
        for chip in ("", "0x6846", "6846\ncfe 5", "123456789", "abcd"):
            with self.subTest(chip=chip):
                self.run_tool("-c", chip, success=False)

    def test_metadata_injection_and_overflow(self):
        self.output.write_bytes(b"old image")
        for option in ("-m", "-a", "-r", "-u", "-g"):
            for value in ("", "x\ncfe 1", "x\r", "x\t", "x\x7f", "\u00e5", "x" * 1024):
                with self.subTest(option=option, value=value[:20]):
                    self.run_tool(option, value, success=False)
                    self.assertEqual(self.output.read_bytes(), b"old image")

    def test_header_text_limit(self):
        self.run_tool()
        text = self.output.read_bytes()[:1024].split(b"\0", 1)[0]
        release = "R" * (1004 - len(text) + len("OpenWrt"))
        self.run_tool("-r", release)
        self.check_image(self.payload)
        saved = self.output.read_bytes()
        self.run_tool("-r", release + "R", success=False)
        self.assertEqual(self.output.read_bytes(), saved)

    def test_invalid_inputs(self):
        for payload in (b"", b"UBI#\x01", b"UBI#\x02" + bytes(59), bytes(128)):
            self.input.write_bytes(payload)
            self.run_tool(success=False)
        self.run_tool("-i", str(self.directory / "absent"), success=False)
        self.run_tool("-i", str(self.directory), success=False)
        self.assertFalse(self.output.exists())

    def test_input_output_aliases(self):
        self.run_tool("-o", str(self.input), success=False)
        self.output.hardlink_to(self.input)
        self.run_tool(success=False)
        self.output.unlink()
        self.output.symlink_to(self.input)
        self.run_tool(success=False)
        self.assertEqual(self.input.read_bytes(), self.payload)

    def test_output_errors_leave_no_temporary(self):
        self.output.mkdir()
        self.run_tool(success=False)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(list(self.directory.glob("output.y3.*")), [])
        self.run_tool("-o", str(self.directory / "missing" / "file"), success=False)

    def test_write_failure_preserves_old_output(self):
        def limit_output():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1500, 1500))

        self.output.write_bytes(b"old image")
        self.run_tool(success=False, preexec_fn=limit_output)
        self.assertEqual(self.output.read_bytes(), b"old image")
        self.assertEqual(list(self.directory.glob("output.y3.*")), [])

    def test_output_permissions(self):
        self.run_tool(preexec_fn=lambda: os.umask(0o027))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o640)

    def test_vendor_payloads(self):
        if not VENDORS:
            self.skipTest("no optional --vendor images supplied")
        for path in VENDORS:
            with self.subTest(path=path):
                vendor = path.read_bytes()
                self.assertEqual(vendor[-32:], hashlib.md5(vendor[:-32]).hexdigest().encode())
                lines = vendor[:1024].split(b"\0", 1)[0].decode().splitlines()
                self.assertEqual(lines.pop(0), "IntenoIopY")
                tags = dict(line.split(" ", 1) for line in lines if line)
                self.assertEqual(tags["version"], "8")
                start, length = int(tags["ubiofs"]), int(tags["ubi"])
                payload = vendor[start:start + length]
                self.assertEqual(len(payload), length)
                self.input.write_bytes(payload)
                self.run_tool("-c", tags["chip"], "-m", tags["model"], "-a", tags["arch"])
                self.check_image(payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--vendor", action="append", type=Path, default=[])
    args = parser.parse_args()
    BINARY, VENDORS = args.binary.resolve(), args.vendor
    unittest.main(argv=[__file__], verbosity=2)
