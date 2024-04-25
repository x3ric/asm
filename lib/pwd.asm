section .text
    global pwd

pwd:
    ; rdi: Pointer to the buffer
    ; rsi: Length of the buffer
    mov rax, 79     ; syscall number for getcwd
    syscall         ; Invoke syscall to get the current working directory
    ret             ; Return from the function
