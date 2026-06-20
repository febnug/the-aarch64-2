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
    ENTRY_OFF = 0x6c
    total_size = 0x78

    h = bytearray(HDRSZ)

    # ELF ident
    h[0:4] = b"\x7fELF"
    h[4] = 2
    h[5] = 1
    h[6] = 1

    # ELF header
    struct.pack_into("<H", h, 0x10, 2)              # ET_EXEC
    struct.pack_into("<H", h, 0x12, 0xb7)           # AArch64
    struct.pack_into("<I", h, 0x14, 1)              # e_version
    struct.pack_into("<Q", h, 0x18, BASE + ENTRY_OFF)
    struct.pack_into("<Q", h, 0x20, 0x38)           # e_phoff

    # /bin/sh in ELF header
    h[0x28:0x30] = BINSH

    struct.pack_into("<I", h, 0x30, 0)
    struct.pack_into("<H", h, 0x34, 64)
    struct.pack_into("<H", h, 0x36, 56)

    # PHDR starts at 0x38, overlapped with ELF header tail
    struct.pack_into("<H", h, 0x38, 1)              # e_phnum / p_type low
    struct.pack_into("<H", h, 0x3a, 0)
    struct.pack_into("<H", h, 0x3c, 7)              # p_flags RWX
    struct.pack_into("<H", h, 0x3e, 0)

    # PHDR rest
    struct.pack_into("<Q", h, 0x40, 0)              # p_offset
    struct.pack_into("<Q", h, 0x48, BASE)           # p_vaddr
    struct.pack_into("<Q", h, 0x50, BASE)           # p_paddr
    struct.pack_into("<Q", h, 0x58, total_size)     # p_filesz
    struct.pack_into("<Q", h, 0x60, total_size)     # p_memsz

    # p_align = high dword becomes first instruction
    struct.pack_into("<I", h, 0x68, 1)

    # entry @ 0x6c:
    # adr x0, 0x28
    imm = 0x28 - ENTRY_OFF
    struct.pack_into("<I", h, 0x6c, adr_encode(0, imm))

    code = bytearray()
    code += struct.pack("<I", 0xd2801ba8)  # mov x8, #221
    code += struct.pack("<I", 0xd4000001)  # svc #0

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
