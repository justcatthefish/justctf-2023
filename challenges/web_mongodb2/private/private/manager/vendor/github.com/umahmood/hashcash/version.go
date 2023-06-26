package hashcash

import "fmt"

// Semantic versioning - http://semver.org/
const (
	Major = 1
	Minor = 0
	Patch = 0
)

// Version returns library version.
func Version() string {
	return fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
}
