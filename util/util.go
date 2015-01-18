package util

import (
	"crypto/rand"
	"io"
)

// RandBytes attempts to read the selected number of bytes from the
// operating system PRNG.
func RandBytes(n int) ([]byte, error) {
	r := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Zero attempts to zeroise a byte slice.
func Zero(in []byte) {
	for i := range in {
		in[i] = 0
	}
}
