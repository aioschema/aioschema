// sha3.go — SHA3-256 (Keccak-f[1600]) implementation for AIOSchema.
//
// Pure Go. Zero external dependencies. Implements FIPS 202 SHA3-256.
// This replaces the golang.org/x/crypto/sha3 dependency entirely.

package aioschema

// SHA3-256 constants (FIPS 202)
const (
	sha3Rate256    = 136 // rate in bytes for SHA3-256 (1088 bits)
	sha3OutputSize = 32  // output size in bytes
)

// Keccak-f round constants
var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// Rotation offsets
var keccakRho = [24]uint{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

// Pi permutation indices
var keccakPi = [24]uint{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

func rotl64(x uint64, n uint) uint64 {
	return (x << n) | (x >> (64 - n))
}

// keccakF1600 applies the Keccak-f[1600] permutation in-place.
func keccakF1600(state *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		// Theta
		for i := 0; i < 5; i++ {
			bc[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				state[j+i] ^= t
			}
		}
		// Rho and Pi
		t := state[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			bc[0] = state[j]
			state[j] = rotl64(t, keccakRho[i])
			t = bc[0]
		}
		// Chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = state[j+i]
			}
			for i := 0; i < 5; i++ {
				state[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}
		// Iota
		state[0] ^= keccakRC[round]
	}
}

// sha3_256Sum computes the SHA3-256 digest of data.
// Pure Go implementation — no external dependencies.
func sha3_256Sum(data []byte) [32]byte {
	var state [25]uint64
	rate := sha3Rate256

	// Absorb
	buf := make([]byte, len(data))
	copy(buf, data)

	// Pad with SHA3 domain separation (0x06) and rate padding (0x80)
	buf = append(buf, 0x06)
	for len(buf)%rate != 0 {
		buf = append(buf, 0x00)
	}
	buf[len(buf)-1] |= 0x80

	// XOR input into state and permute
	for len(buf) >= rate {
		for i := 0; i < rate/8; i++ {
			state[i] ^= uint64(buf[i*8]) |
				uint64(buf[i*8+1])<<8 |
				uint64(buf[i*8+2])<<16 |
				uint64(buf[i*8+3])<<24 |
				uint64(buf[i*8+4])<<32 |
				uint64(buf[i*8+5])<<40 |
				uint64(buf[i*8+6])<<48 |
				uint64(buf[i*8+7])<<56
		}
		keccakF1600(&state)
		buf = buf[rate:]
	}

	// Squeeze — extract 32 bytes
	var out [32]byte
	for i := 0; i < 4; i++ {
		v := state[i]
		out[i*8+0] = byte(v)
		out[i*8+1] = byte(v >> 8)
		out[i*8+2] = byte(v >> 16)
		out[i*8+3] = byte(v >> 24)
		out[i*8+4] = byte(v >> 32)
		out[i*8+5] = byte(v >> 40)
		out[i*8+6] = byte(v >> 48)
		out[i*8+7] = byte(v >> 56)
	}
	return out
}
