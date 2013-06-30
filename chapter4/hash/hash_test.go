package hash

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

var (
	helloTestVector = []byte("Hello, world.")
	helloBinDigest  = []byte{
		0xf8, 0xc3, 0xbf, 0x62, 0xa9, 0xaa, 0x3e, 0x6f, 
		0xc1, 0x61, 0x9c, 0x25, 0x0e, 0x48, 0xab, 0xe7, 
		0x51, 0x93, 0x73, 0xd3, 0xed, 0xf4, 0x1b, 0xe6, 
		0x2e, 0xb5, 0xdc, 0x45, 0x19, 0x9a, 0xf2, 0xef, 
	}
	helloHexDigest = "f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef"
)

func GenFailer(name string, err error, t *testing.T) func(string) {
	return func(msg string) {
		if msg == "" {
			fmt.Printf("%s: failed: %s\n", name, err.Error())
		} else {
			fmt.Printf("%s: failed: %s\n", name, msg)
		}
		t.FailNow()
	}
}

func sampleReader(src []byte) io.Reader {
	if src == nil {
		src = helloTestVector
	}
	b := bytes.NewBuffer(src)
	return b
}

func TestNewHash(t *testing.T) {
	fail := GenFailer("TestNewHash", nil, t)
	h := New(helloTestVector)
	if !bytes.Equal(h.Digest(), helloBinDigest) {
		fail("test vector doesn't match hash")
	}

	if string(h.HexDigest()) != helloHexDigest {
		fail("test hex digest doesn't match hash")
	}
}

func TestReadHash(t *testing.T) {
	var err error

	fail := GenFailer("TestReadHash", err, t)
	r := sampleReader(nil)
	h, err := Read(r)
	if err != nil {
		fail("")
	} else if !bytes.Equal(h.Digest(), helloBinDigest) {
		fail("test vector doesn't match hash")
	}
}

func TestVerifyHash(t *testing.T) {
	fail := GenFailer("TestVerifyHash", nil, t)
	h := New(helloTestVector)
	if !h.Verify(helloTestVector) {
		fail("Verify() failed for test vector")
	} else if h.Verify([]byte("Hello, world?")) {
		fail("Verify() should have failed for test vector")
	}
}

func TestVerifyReadHash(t *testing.T) {
	fail := GenFailer("TestVerifyReadHash", nil, t)
	r := sampleReader(nil)

	h := New(helloTestVector)
	if !h.VerifyRead(r) {
		fail("VerifyRead() failed for test vector")
	}

	r = sampleReader([]byte("Hello, world?"))
	if h.VerifyRead(r) {
		fail("VerifyRead() should have failed for test vector")
	}
}
