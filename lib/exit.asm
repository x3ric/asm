section .text
    global exit

exit: 
    ; rdi: Exit code
    mov rax, 60   ; Set syscall number for exit (60 for x86-64 Linux)
    syscall       ; Invoke syscall to exit the program