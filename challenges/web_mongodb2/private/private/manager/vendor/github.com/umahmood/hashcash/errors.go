package hashcash

import "errors"

var (
	// ErrSolutionFail error cannot compute a solution
	ErrSolutionFail = errors.New("exceeded 2^20 iterations failed to find solution")

	// ErrResourceEmpty error empty hashcash resource
	ErrResourceEmpty = errors.New("empty hashcash resource")

	// ErrInvalidHeader error invalid hashcash header format
	ErrInvalidHeader = errors.New("invalid hashcash header format")

	// ErrNoCollision error n 5 most significant hex digits (n most significant
	// bits are not 0.
	ErrNoCollision = errors.New("no collision most significant bits are not zero")

	// ErrTimestamp error futuristic and expired time stamps are rejected
	ErrTimestamp = errors.New("time stamp is too far into the future or expired")

	// ErrResourceFail error hashcash resource data did not pass validation
	ErrResourceFail = errors.New("resource data did not pass validation")

	// ErrSpent error avoid accepting the same stamp twice
	ErrSpent = errors.New("hashcash has already been spent")
)
