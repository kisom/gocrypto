package main

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter4/hash"
	"os"
)

var (
	algorithm crypto.Hash
	files     []string
)

func matchAlgo(a int) crypto.Hash {
	switch a {
	case 1:
		return crypto.SHA1
	case 256:
		return crypto.SHA256
	case 512:
		return crypto.SHA512
	default:
		fmt.Printf("[!] invalid algorithm. Valid algorithms ")
		fmt.Printf(" are 1, 256, and 512")
		os.Exit(1)
	}
	panic("not reached")
}

func init() {
	flagAlgo := flag.Int("a", 512, "algorithm to use for hashing")
	flag.Parse()
	algorithm = matchAlgo(*flagAlgo)
	fmt.Printf("algo: %+v\n", algorithm)
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

		h, err := hash.ReadWith(file, algorithm)
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
