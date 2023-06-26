## Mystery locker

tldr; heap null byte write

Menu:
- create file
- rename file
- print file (aka leak)
- delete file

It is possible to overwrite last byte of tcache ptr and overlap some chunks - this can lead to heap address leak.
Next target is to leak binary base (because there are some pointers on the heap).
Once binary address is known it is possible to leak libc address from .bss section of binary.
Finally, pointers on heap can be overwritten to obtain code execution.
