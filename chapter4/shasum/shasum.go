package main

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
)

const ReadSize = 4096

var (
	algorithm func() hash.Hash
	files     []string
)

type Digest []byte

// Return the hex version of a digest.
func (h Digest) HexDigest() string {
	return fmt.Sprintf("%x", h)
}

// Read computes a new digest from the contents of a Reader.
func HashReader(r io.Reader, algo func() hash.Hash) (h Digest, err error) {
	c := algo()

	for {
		var n int
		buf := make([]byte, ReadSize)

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
	h = c.Sum(nil)
	return
}

func matchAlgo(a int) func() hash.Hash {
	switch a {
	case 1:
		return crypto.SHA1.New
	case 224:
		return crypto.SHA256.New224
	case 256:
		return crypto.SHA256.New
	case 512:
		return crypto.SHA512.New
	default:
		fmt.Printf("[!] invalid algorithm. Valid algorithms ")
		fmt.Printf(" are 1, 224, 256, 384, and 512")
		os.Exit(1)
	}
	panic("not reached")
}

func init() {
	flagAlgo := flag.Int("a", 512, "algorithm to use for hashing")
	flag.Parse()
	algorithm = matchAlgo(*flagAlgo)
	files = flag.Args()

	if len(files) == 0 {
		os.Exit(0)
	}
}

func main() {
	var errorList = make([]string, 0)

	for _, filename := range files {
		file, err := os.Open(filename)
		if err != nil {
			errorList = append(errorList,
				fmt.Sprintf("%s: %s\n", filename, err.Error))
			continue
		}
		defer file.Close()

		h, err := HashReader(file, algorithm)
		if err != nil {
			errorList = append(errorList,
				fmt.Sprintf("%s: %s", filename, err.Error))
			continue
		}
		fmt.Printf("%s  %s\n", string(h.HexDigest()), filename)
	}

	if len(errorList) != 0 {
		fmt.Println("\nErrors:\n")
		for _, e := range errorList {
			fmt.Println(e)
		}
	}
}
