package hash

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"fmt"
	"io"
)

const DefaultAlgo = crypto.SHA512

type Digest struct {
	digest []byte
	algo   crypto.Hash
}

// New computes a new digest computed from the byte slice passed in with the
// algorithm specified by DefaultAlgo.
func New(buf []byte) Digest {
	return NewWith(buf, DefaultAlgo)
}

// NewWith returns a new digest computed from the byte slice passed in with
// the specified algorithm.
func NewWith(buf []byte, algo crypto.Hash) Digest {
	c := algo.New()
	c.Write(buf)
	return Digest{c.Sum(nil), algo}
}

// Read computes a new SHA-512 digest from the reader passed in.
func Read(r io.Reader) (h Digest, err error) {
	return ReadWith(r, DefaultAlgo)
}

// Read computes a new digest computed from the reader with the specified
// algorithm.
func ReadWith(r io.Reader, algo crypto.Hash) (h Digest, err error) {
	c := algo.New()

	for {
		var n int
		buf := make([]byte, sha512.BlockSize)

		n, err = r.Read(buf)
		if err != nil && err != io.EOF {
			return
		}
		c.Write(buf[:n])
		if err == io.EOF {
			err = nil
			break
		}
	}
	h = Digest{c.Sum(nil), algo}
	return
}

// The Digest method returns the binary SHA-512 digest.
func (h Digest) Digest() []byte {
	return h.digest
}

// The HexDigest method returns a hexadecimal version of the SHA-512 digest.
func (h Digest) HexDigest() []byte {
	hexHash := make([]byte, 0)
	for _, b := range h.digest {
		ch := fmt.Sprintf("%02x", b)
		hexHash = append(hexHash, []byte(ch)...)
	}
	return hexHash
}

// Verify compares the SHA-512 digest to the SHA-512 digest computed from the
// byte slice passed in.
func (h Digest) Verify(buf []byte) bool {
	vHash := NewWith(buf, h.algo)
	if !bytes.Equal(vHash.digest, h.digest) {
		return false
	}
	return true
}

// VerifyRead compares the SHA-512 digest to the SHA-512 digest computer from
// byte slice passed in.
func (h Digest) VerifyRead(r io.Reader) bool {
	vHash, err := ReadWith(r, h.algo)
	if err != nil {
		return false
	} else if !bytes.Equal(vHash.digest, h.digest) {
		return false
	}
	return true
}
