.arch armv8-a
.text
.global _start

ehdr:
    .byte 0x7f,'E','L','F'
    .byte 2,1,1,0
    .quad 0

    .hword 2
    .hword 0xb7
    .word 1
    .quad _start
    .quad phdr - ehdr
    .quad 0
    .word 0
    .hword 64
    .hword 56
    .hword 1
    .hword 0
    .hword 0
    .hword 0

phdr:
    .word 1
    .word 5
    .quad 0
    .quad ehdr
    .quad ehdr
    .quad filesize
    .quad filesize
    .quad 0x1000

_start:
    mov x0, #1
    adr x1, msg
    mov x2, #2
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #93
    svc #0

msg:
    .ascii "FN"

filesize = . - ehdr
