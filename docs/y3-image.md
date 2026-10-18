# y3-image

`y3-image` packages a prepared UBI image in the legacy Inteno/Genexis Y3
version-8 format. It is intended for OpenWrt factory images using the
`singlepureubi bpartit32` layout. It does not generate UBI, UBIFS, kernels,
Broadcom boot bundles, or boot metadata. Its input is copied unchanged.

The output contains a 1024-byte NUL-padded text header, the UBI payload,
and a 32-byte lowercase hexadecimal MD5 over the header and payload. All
offsets are absolute byte offsets in the Y3 file. There is no timestamp,
random identifier, signature, or installation script.

## Building and testing

Build with the repository's CMake configuration, or build just this tool:

```sh
cc -O2 -Wall -Wextra -o y3-image src/y3-image.c src/md5.c
python3 tests/test_y3_image.py ./y3-image
```

The tests use Python's independent MD5 implementation. Optional
`--vendor FILE.y3` arguments verify existing legacy vendor checksums,
extract their UBI sections and check that repackaging preserves those
sections exactly. Vendor firmware files are not included in this repository.

## Genexis XG6846B example

Given a complete `openwrt-xg6846b.ubi`, prepared by the board image recipe:

```sh
y3-image -i openwrt-xg6846b.ubi -o openwrt-xg6846b.y3 \
  -c 6846 -m PANTHER -a 'all arm_xscale' \
  -r OpenWrt-SNAPSHOT -u GNX -g '<source-revision>'
```

Chip, model and architecture identifiers are supplied by the caller, so
the packager can also serve other routers using this Y3 layout. Use the
identifiers expected by the target firmware, which may differ from the
OpenWrt build architecture or marketing name. This does not imply support
for newer GenXOS loader/bootfs migration images or signed-only updaters.

For the XG6846B single-bank layout, the prepared UBI image should contain:

| Volume ID | Name | Type | Contents |
|---:|---|---|---|
| 0 | `rootfs_0` | dynamic | OpenWrt UBIFS root filesystem |
| 1 | `METADATA` | dynamic | Committed bank-0 metadata |
| 2 | `METADATACOPY` | dynamic | Redundant bank-0 metadata |
| 10 | `kernel_0` | static | Broadcom boot bundle |

`kernel_0` must include the existing **`cferam.000`** RAM-stage loader,
alongside the appropriately wrapped new kernel (`vmlinux.lz`) and board
DTB (`96846.dtb`). The first 4 MiB alone does not contain the complete CFE
boot chain. Volume names, IDs, filesystem sizing and boot records are the
board recipe's responsibility; this utility only checks the input's UBI
magic and version, not its volume layout or bootability.

Writable UBIFS can use the remaining UBI space without a second rootfs or
a separate `rootfs_data` volume. The board recipe should generate a compact
UBI image with rootfs autoresize, not pad the file to NAND capacity. The
default maximum **total Y3 size** is `0x03a20000` (58.125 MiB), the limit in
the examined XG6846B CFE. `-s` can set another target's limit, up to
`INT32_MAX`; increasing it does not change the target bootloader's limit.

## Loader preservation and installation

The header explicitly sets `cfe`, `rescue`, `vmlinux` and `ubifs` section
lengths to zero: the kernel and filesystem are inside the sole `ubi`
payload. No option adds a replacement CFE ROM, rescue or newer-style loader
payload. The required zero-length section fields and offsets remain in
the header because the CFE parser requires some of them even when absent.

Static analysis of XG6846B CFE `1.0.38-164.255-IOP2.2` shows that its
singlepureubi Y3 installer skips ROM/rescue replacement for these lengths,
erases the whole old UBI area, writes the new UBI image and commits its
first bank. On the 256 MiB NAND with 128 KiB eraseblocks, that UBI area is
`[0x00400000, 0x0ff80000)`. The final 512 KiB reserved for bad-block tables
is excluded. The kernel partition definition and UBI sizing must agree
with the intended target geometry.

**The stock CFE installer still rewrites NVRAM in the first 4 MiB.** An
image with no ROM payload preserves loader code, but does not guarantee
that region is byte-for-byte unchanged or never erased. For a strict
no-write requirement below `0x00400000`, a separate RAM-resident installer
must extract the UBI section and write only the UBI MTD partition.

The vendor Linux `sysupgrade` instead extracts individual volumes and
updates an alternate bank. Giving it a single-bank Y3 does not cause it to
replace the complete existing UBI layout. These are installer behaviors,
not actions that a Y3 container can enforce.

Do not append an OpenWrt metadata trailer after the Y3 checksum: the CFE
parser checks the total length and expects the MD5 in the final 32 bytes.
Successful packaging and checksum verification do not validate the new
kernel's load address, DTB handoff, root mount or hardware operation.
