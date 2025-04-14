BITS 64
section .text
global _start

_start:
    xor rax, rax ; 48 31 c0 
    push rax ; 50 
    movabs rbx, 0x6477702f6e69622f ; 48 bb 2f 62 69 6e 2f 70 77 64 
    push rbx ; 53 
    mov rdi, rsp ; 48 89 e7 
    xor rax, rax ; 48 31 c0 
    push rax ; 50 
    push rdi ; 57 
    mov rsi, rsp ; 48 89 e6 
    xor rdx, rdx ; 48 31 d2 
    mov eax, 0x3b ; b8 3b 00 00 00 
    syscall  ; 0f 05 
