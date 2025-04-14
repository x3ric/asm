BITS 64
section .text
global _start

_start:
    mov rax, 1 ; 48 c7 c0 01 00 00 00 
    mov rdi, 1 ; 48 c7 c7 01 00 00 00 
    lea rsi, [rel message] ; 48 8d 35 0a 00 00 00 
    mov rdx, 0xf ; 48 c7 c2 0f 00 00 00 
    syscall  ; 0f 05 
    mov rax, 0x3c ; 48 c7 c0 3c 00 00 00 
    xor rdi, rdi ; 48 31 ff 
    syscall  ; 0f 05 
message:
    db 'Hello assembly!', 0x0a
