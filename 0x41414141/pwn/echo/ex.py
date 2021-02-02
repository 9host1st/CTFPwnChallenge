from pwn import *
p = process("./echo")
elf = ELF("./echo")

syscall = 0x40104c
    
p.interactive()
