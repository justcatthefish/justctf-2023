# Hashcash

Hashcash is a Go library which implements the hashcash algorithm. Hashcash is a 
proof-of-work algorithm, which has been used as a denial-of-service counter 
measure technique in a number of systems. To learn more about hashcash, 
go [here](http://hashcash.org/).

# Installation

> go get github.com/umahmood/hashcash

# Usage

Computing a hashcash:
```
package main

import (
    "fmt"
    
    "github.com/umahmood/hashcash"
)

func validateResource(resource string) bool {
    // validate resource. resource could be an email, ip 
    // address, etc... so for an email we could check it 
    // exists in the database.
    return true
}

func main() {
    hc, err := hashcash.New(
        &hashcash.Resource{
            Data:          "someone@gmail.com",
            ValidatorFunc: validateResource,
        },
        nil, // use default config.
    )
    if err != nil {
        // handle error
    }
    
    solution, err := hc.Compute()
    if err != nil {
        if err != hashcash.ErrSolutionFail {
            // did not find a solution, can call compute again.
        }
    } 
    fmt.Println(solution)
}
```
Output:
```
1:20:040806:foo::65f460d0726f420d:13a6b8
```
```
$ echo -n "1:20:040806:foo::65f460d0726f420d:13a6b8" | shasum
00000f91d51a9c213f9b7420c35c62b5e818c23e
```
Verifying a hashcash:
```
valid, err := hc.Verify(solution)
if err != nil {
    // handle error
}
if !valid {
   // hashcash token failed verification.
}
```
Storage:

In order to detect double spending, hashcash stores verified hashcash tokens in 
a sqlite3 database. This database is stored in ~/.hashcash/spent.db.

If you would like to change the underlying storage (i.e. to an in memory hash 
table) or location. You will need to build a type which satisfies the *Storage* 
interface.

# To Do

- Allow entries in default storage (sqlite3 database) to be purged.

# Documentation

http://godoc.org/github.com/umahmood/hashcash

# License

See the [LICENSE](LICENSE.md) file for license rights and limitations (MIT).
