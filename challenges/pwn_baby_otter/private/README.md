## Baby Otter

the idea is that the players can become otter owners by introducing a secret code, which can be found in the challenge source:
```
assert!(ownership_code_hash == 1725720156, ERR_INVALID_CODE);
```
The way `ownership_code_hash` is generated is by passing it to the hh function (which implements the `CRC32` hash). So The goal is for them to identify this function, and then crack this hash using a 4 bytes bruteforce. After they obtain the word H4CK, they must call from the solution contract the function `baby_otter_challenge::request_ownership` with this parameter and then the challenge will send them back the flag.
