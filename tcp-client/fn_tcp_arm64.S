// fn_tcp_arm64.S
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
    // socket(AF_INET, SOCK_STREAM, 0)
    mov x0, #2
    mov x1, #1
    mov x2, #0
    mov x8, #198
    svc #0

    mov x19, x0

    // sockaddr_in:
    // family AF_INET = 2
    // port 4444 = 0x115c big endian => bytes 11 5c
    // addr 127.0.0.1 = 7f 00 00 01
    adr x1, sa
    mov x0, x19
    mov x2, #16
    mov x8, #203
    svc #0

    // write(fd, "FN", 2)
    mov x0, x19
    adr x1, msg
    mov x2, #2
    mov x8, #64
    svc #0

    // exit(0)
    mov x0, #0
    mov x8, #93
    svc #0

sa:
    .byte 2, 0
    .byte 0x11, 0x5c
    .byte 127, 0, 0, 1
    .quad 0

msg:
    .ascii "FN"

filesize = . - ehdr
