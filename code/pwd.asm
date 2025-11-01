BITS 64
section .text
global _start
_start:
    xor rax,rax
    push rax
    mov rbx,0x6477702f6e69622f
    push rbx
    mov rdi,rsp
    xor rax,rax
    push rax
    push rdi
    mov rsi,rsp
    xor rdx,rdx
    mov eax,0x3b
    syscall
