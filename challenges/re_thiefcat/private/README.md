# thiefcat

A very fun challenge requiring a deep dive into how exception handling works on Linux.

A VM can be constructed using the exception table unwind information. We can freely change registers, read memory and compute expressions, however we can not directly write memory. Therefore we need to ensure that somewhere in the binary there is some primitive that allows us to write memory.

I put the following gadget into the exception handler in the main function:
```
	mov  QWORD PTR [rbp], rbx
	mov  rax, [rsp+8]
	mov  [rsp], rax
	mov  rbp, rsp
	leave
	ret
```

It looks rather innocuous, but upon closer inspection it:
- does *rbp = *rbx (both registers can be set from DWARF)
- sets rax to the value of rsp+8 (which can be set using the previous primitive), and esentially jumps to it

Which allows us to create an exception loop that allows us to write a single qword to memory every iteration.

The task itself is a netcat-like binary, that takes an IP address and port and connects us to a server. The binary tries to read a line from the remote server and if it's too long, it throws an exception and begins executing code hidden in the unwind info. The buffer sent from the server contains an encryption key. The hidden code resolves some extra symbols from libc, reads flag.txt, deletes it and encrypts the sends the contents encrypted with the key provided by the server.

The source code for the program converting source code to DWARF will not be released.
A custom language was created for this purpose. The reference source code for the program itself can be found in the private folder. 