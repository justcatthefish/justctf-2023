/*
Package hashcash a library which implements the hashcash proof-of-work algorithm.

Computing a hashcash:

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

Verifying a hashcash:

    valid, err := hc.Verify(solution)
    if err != nil {
        // handle error
    }
    if !valid {
       // hashcash token failed verification.
    }
*/
package hashcash
