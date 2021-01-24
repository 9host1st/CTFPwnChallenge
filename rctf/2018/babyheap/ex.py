from pwn import *
p = process("./babyheap")
elf = ELF("./babyheap")
libc = elf.libc

def malloc(size, content):
    p.sendlineafter(": ", "1")
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", content)

def show(idx):
    p.sendlineafter(": ", "2")
    p.sendlineafter("index: ", str(idx))

def delete(idx):
    p.sendlineafter(": ", "3")
    p.sendlineafter("index: ", str(idx))

if __name__ == "__main__":
    malloc(96, "a" * 96)
    pause()
    p.interactive()
