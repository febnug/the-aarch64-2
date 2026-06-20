#!/usr/bin/env python3
import struct, os

BASE = 0x10000
HDRSZ = 112
OUT = "aarch64_execve_tiny"
BINSH = b"/bin/sh\x00"

def adr_encode(rd, imm21):
    imm21 &= 0x1fffff
    immlo = imm21 & 3
    immhi = (imm21 >> 2) & 0x7ffff
    return 0x10000000 | (immlo << 29) | (immhi << 5) | rd

def build():
    h = bytearray(HDRSZ)

    # ELF ident
    h[0:4] = b"\x7fELF"
    h[4] = 2      # 64-bit
    h[5] = 1      # little-endian
    h[6] = 1      # version

    # ELF header
    struct.pack_into("<H", h, 0x10, 2)          # ET_EXEC
    struct.pack_into("<H", h, 0x12, 0xb7)       # AArch64
    struct.pack_into("<I", h, 0x14, 1)
    struct.pack_into("<Q", h, 0x18, BASE + HDRSZ)
    struct.pack_into("<Q", h, 0x20, 0x38)       # phoff

    # store "/bin/sh\0" in unused ELF header area
    h[0x28:0x30] = BINSH

    struct.pack_into("<I", h, 0x30, 0)
    struct.pack_into("<H", h, 0x34, 64)
    struct.pack_into("<H", h, 0x36, 56)

    # overlap ELF header tail with PHDR start
    struct.pack_into("<H", h, 0x38, 1)          # e_phnum + p_type low
    struct.pack_into("<H", h, 0x3a, 0)
    struct.pack_into("<H", h, 0x3c, 7)          # p_flags RWX
    struct.pack_into("<H", h, 0x3e, 0)

    total_size = HDRSZ + 16

    # PHDR rest
    struct.pack_into("<Q", h, 0x40, 0)          # p_offset
    struct.pack_into("<Q", h, 0x48, BASE)       # p_vaddr
    struct.pack_into("<Q", h, 0x50, BASE)       # p_paddr
    struct.pack_into("<Q", h, 0x58, total_size)
    struct.pack_into("<Q", h, 0x60, total_size)
    struct.pack_into("<Q", h, 0x68, 1)          # p_align

    code = bytearray()

    # adr x0, header+/bin/sh
#    imm = 0x28 - HDRSZ
#    code += struct.pack("<I", adr_encode(0, imm))

    # mov x1, xzr
#    code += struct.pack("<I", 0xaa1f03e1)

    # mov x8, #221
#    code += struct.pack("<I", 0xd2801ba8)

    # svc #0
#    code += struct.pack("<I", 0xd4000001)

    # adr x0, header+/bin/sh
    imm = 0x28 - HDRSZ
    code += struct.pack("<I", adr_encode(0, imm))

    # mov x8, #221
    code += struct.pack("<I", 0xd2801ba8)

    # svc #0
    code += struct.pack("<I", 0xd4000001)

    return bytes(h) + bytes(code)

def main():
    elf = build()
    with open(OUT, "wb") as f:
        f.write(elf)
    os.chmod(OUT, 0o755)

    print(f"[+] wrote {OUT}")
    print(f"[+] size: {len(elf)} bytes")
    print("[+] test:")
    print(f"    file {OUT}")
    print(f"    readelf -h -l {OUT}")
    print(f"    qemu-aarch64 ./{OUT}")

if __name__ == "__main__":
    main()
