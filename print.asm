section .text
    global _start
    extern print
    extern exit

_start:
    mov rsi, [rsp + 16]  ; Load the command line argument into rsi
    call print           ; Call the print function with the command line argument
    mov rsi, 0           ; Set rsi to 0 for exit status
    call exit            ; Call the exit function to terminate the program
