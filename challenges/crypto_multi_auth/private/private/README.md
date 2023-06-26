## Multi Auth

The task is about misues of cryptographic APIs.

#### HMAC part
Key is swapped with message, and HMAC has a property that `HMAC(long_key, msg) == HMAC(hash(long_key), msg)`.
APIs may protect against incorrect order of arguments only in typed languages.

#### ECDSA part
ECDSA requires hashing message before calling sign/verify methods. Otherwise, in most APIs it silently truncates
the input and effectively authenticates only `size(base point's order)` bytes.

#### AES part
NIST specification specifies a few allowed authenticated tags lengths. The default one is 16 bytes, the
shortest one is only 4 bytes. Some APIs support all allowed tags-lengths by default, and users are
expected to explicitly set desired lengths.

Bruteforcing 4 bytes (or performing smarter key recovery attack) is tedious for CTF, so I let users "leak"
3 bytes for free with a "backdoor" method. The task could be extended with less obvious "leak"
(e.g., via padding in structures).