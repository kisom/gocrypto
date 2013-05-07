package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter6/timethief/badcrypto"
	"io/ioutil"
	"os"
	"strings"
)

var (
	ErrWrite = fmt.Errorf("write error")
	key      []byte
)

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

func genkey(filename string) {
	var err error

	key, err = badcrypto.GenerateKey()
	if err != nil {
		fmt.Println("[!] failed to generate key:", err.Error())
		os.Exit(1)
	}
	fmt.Println("[+] generating new key")
	err = ioutil.WriteFile(filename, key, 0600)
	if err != nil {
		fmt.Println("[!] failed to write key:", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	shouldDecrypt := flag.Bool("d", false, "decrypt the input file")
	shouldEncrypt := flag.Bool("e", false, "encrypt the input file")
	genKeyFile := flag.String("genkey", "", "generate a new key")
	keyFile := flag.String("k", "", "key file")
	inFile := flag.String("in", "", "input file")
	outFile := flag.String("out", "", "output file")
	flag.Parse()

	var err error
	if *keyFile == "" && *genKeyFile == "" {
		fmt.Println("[!] no key specified and not generating a key, nothing to do.")
		os.Exit(1)
	} else if *keyFile != "" {
		key, err = ioutil.ReadFile(*keyFile)
		if err != nil {
			fmt.Println("[!]", err.Error())
			os.Exit(1)
		}
	} else if *genKeyFile != "" {
		genkey(*genKeyFile)
	}

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

	if *shouldDecrypt {
		err = badcrypto.DecryptFile(*inFile, *outFile, key)
	} else {
		err = badcrypto.EncryptFile(*inFile, *outFile, key)
	}

	if err != nil {
		fmt.Printf("[!] %s\n", err.Error())
	} else {
		fmt.Println("[+] ok")
	}
}
