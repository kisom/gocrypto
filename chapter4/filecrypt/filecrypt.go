package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/symmetric"
	"github.com/kisom/gocrypto/chapter4/hash"
	"io"
	"os"
	"strings"
)

var ErrWrite = fmt.Errorf("write error")

func readPrompt(prompt string) (input string, err error) {
	fmt.Printf(prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	input = strings.TrimSpace(line)
	return
}

func main() {
	shouldDecrypt := flag.Bool("d", false, "decrypt the input file")
	shouldEncrypt := flag.Bool("e", false, "encrypt the input file")
	inFile := flag.String("in", "", "input file")
	outFile := flag.String("out", "", "output file")
	flag.Parse()

	if len(*inFile) == 0 {
		fmt.Println("[!] no input file specified (specify one with -in)")
		os.Exit(1)
	} else if len(*outFile) == 0 {
		fmt.Println("[!] no output file specified (specify one with -out)")
	}

	if (!*shouldDecrypt) && (!*shouldEncrypt) {
		fmt.Println("[!] no mode specified: specify encryption with -e and")
		fmt.Println("    decryption with -d.")
		os.Exit(1)
	} else if *shouldDecrypt && *shouldEncrypt {
		fmt.Println("[!] only one mode should be specified; either encrypt")
		fmt.Println("    or decrypt.")
		os.Exit(1)
	}

	passphrase, err := readPrompt("Passphrase: ")
	if err != nil {
		fmt.Println("[!] error reading passphrase:", err.Error())
		os.Exit(1)
	}

	if *shouldDecrypt {
		err = decryptFile(*inFile, *outFile, passphrase)
	} else {
		err = encryptFile(*inFile, *outFile, passphrase)
	}

	if err != nil {
		fmt.Printf("[!] %s\n", err.Error())
	} else {
		fmt.Println("[+] ok")
	}
}

func decryptFile(inFile, outFile, passphrase string) (err error) {
	salt := make([]byte, hash.SaltLength)
	inReader, err := os.Open(inFile)
	if err != nil {
		return
	}
	defer inReader.Close()

	outWriter, err := os.Create(outFile)
	if err != nil {
		return
	}
	defer outWriter.Close()

	_, err := io.ReadFull(inReader, salt)
	if err != nil {
		return
	}

	key := hash.DeriveKeyWithSalt(passphrase, salt)
	err = symmetric.DecryptReader(key.Key, inReader, outWriter)
	return
}

func encryptFile(inFile, outFile, passphrase string) (err error) {
	key := hash.DeriveKey(passphrase)

	inReader, err := os.Open(inFile)
	if err != nil {
		return
	}
	defer inReader.Close()

	outWriter, err := os.Create(outFile)
	if err != nil {
		return
	}
	defer outWriter.Close()

	n, err := outWriter.Write(key.Salt)
	if err != nil {
		return
	} else if n != len(key.Salt) {
		err = ErrWrite
		return
	}

	err = symmetric.EncryptReader(key.Key, inReader, outWriter)
	return
}
