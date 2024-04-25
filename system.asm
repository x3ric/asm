section .text
    global _start
    extern system
    extern exit

_start:
    mov rsi, [rsp + 16]  ; Get command line argument
    
    mov rdi, rsi          ; Set argument for system call
    call system           ; Execute command

    mov rsi, 0            ; Set exit status
    call exit             ; Exit program
