BITS 64
section .text
global _start
_start:
    mov eax,0x1
    mov edi,0x1
    lea rsi,[0x22]
    mov edx,0xf
    syscall
    mov eax,0x3c
    xor rdi,rdi
    syscall
    gs insb
    insb
    outsd
    and [rcx+0x73],ah
    jnc near 0x91
    insd
    db 0x62
    insb
    jns near 0x52
    db 0x0a
