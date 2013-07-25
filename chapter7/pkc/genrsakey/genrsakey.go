package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter7/pkc"
	"os"
)

func main() {
	size := flag.Int("b", 2048, "curve size")
	fileName := flag.String("f", "", "key file name")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, *size)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if *fileName == "" {
		*fileName = fmt.Sprintf("rsa_%d", *size)
	}
	pubKeyName := *fileName + ".pub"
	privKeyName := *fileName + ".key"

	if err := pkc.ExportPrivatePEM(key, privKeyName); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if err := pkc.ExportPublicPEM(&key.PublicKey, pubKeyName); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
