package hashcash

import "time"

// Purger purges hashcash entries from the underlying storage
type Purger interface {
	PurgeExpired(time.Time) error
	PurgeSingle(string) error
	PurgeAll() error
}

// Spender operations which can be performed on storage.
type Spender interface {
	Add(string) error
	Spent(string) bool
}

// Storage store and retrieve hashcash entries
type Storage interface {
	Spender
}
