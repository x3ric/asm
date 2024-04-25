section .bss
    buffer resb 256  ; Reserve 256 bytes for the buffer to store the result

section .text
    global _start
    extern exit
    extern print
    extern pwd

_start:
    mov rdi, buffer   ; Set the buffer address as the argument for pwd
    mov rsi, 256      ; Set the buffer size
    call pwd          ; Call pwd to get the current working directory
    
    mov rsi, buffer   ; Set the buffer address as the argument for print
    call print        ; Print the current working directory

    mov rsi, 0        ; Set exit status
    call exit         ; Exit the program
