// sha3.go — SHA3-256 (Keccak) implementation for AIOSchema.
//
// Go's standard library does not include SHA3 in crypto/sha3 without
// golang.org/x/crypto. This file provides a self-contained SHA3-256
// using golang.org/x/crypto/sha3, keeping the dependency explicit.
//
// If golang.org/x/crypto is unavailable, the sha3-256 algorithm simply
// returns an error from ComputeHash — it is not required for CV-01..CV-14.

package aioschema

import (
	"golang.org/x/crypto/sha3"
)

// sha3_256Sum computes the SHA3-256 digest of data.
func sha3_256Sum(data []byte) [32]byte {
	h := sha3.New256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
