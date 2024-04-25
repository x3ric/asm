section .text
    global print

print:
    ; rsi: Pointer to the message
    xor rcx, rcx         ; Clear rcx register to use as a loop counter
.loop:
    mov al, [rsi + rcx]  ; Load the byte at the current position into al
    cmp al, 0            ; Compare the byte with null terminator
    je .done             ; If null terminator is found, exit loop
    inc rcx              ; Increment loop counter
    jmp .loop            ; Continue looping
.done:
    mov rdx, rcx         ; Move the loop counter (string length) to rdx
    mov byte [rsi + rdx], 10  ; Append newline character to the end of the message
    inc rdx              ; Increment rdx to include the newline character
    mov rax, 1           ; Set rax to 1 for the sys_write syscall
    mov rdi, 1           ; Set rdi to 1 for stdout
    syscall              ; Call the kernel to write the message to stdout
    ret                  ; Return from the function
