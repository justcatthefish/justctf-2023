package hashcash

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
)

// randomBytes reads n cryptographically secure pseudo-random numbers.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// base64EncodeBytes
func base64EncodeBytes(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// base64EncodeInt
func base64EncodeInt(n int) string {
	return base64EncodeBytes([]byte(strconv.Itoa(n)))
}

// sha1Hash
func sha1Hash(s string) string {
	hash := sha1.New()
	_, err := io.WriteString(hash, s)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
