package main

import (
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter6/timethief/badcrypto"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

func random(size int, seed int64) (b []byte, err error) {
	src := rand.NewSource(seed)
	rng := rand.New(src)
	b = make([]byte, 0)
	for i := 0; i < size; i++ {
		b = append(b, byte(rng.Intn(255)))
	}
	return
}

func genkey(seed int64) (key []byte, err error) {
	return random(badcrypto.KeySize, seed)
}

func startTime(duration string) int64 {
	dur, err := time.ParseDuration(duration)
	if err != nil {
		fmt.Printf("[!] failed to parse %s: %s\n", duration, err.Error())
		os.Exit(1)
	}
	return time.Now().Unix() - int64(dur.Seconds())
}

func stopTime(duration string) int64 {
	if duration == "" {
		return time.Now().Unix()
	}

	return startTime(duration)
}

func main() {
	startDur := flag.String("start", "5m", "when to start scanning from")
	stopDur := flag.String("stop", "", "when to stop scanning from")
	inFile := flag.String("in", "", "encrypted file")
	outFile := flag.String("out", "", "savefile")
	flag.Parse()

	start := startTime(*startDur)
	stop := stopTime(*stopDur)

	if *inFile == "" {
		fmt.Println("[!] no input file: nothing to do")
		flag.PrintDefaults()
		os.Exit(1)
	}
	fmt.Printf("[+] starting at %d, stopping at %d, scanning %d seconds\n", start, stop,
		stop-start)
	scan(start, stop, *inFile, *outFile)
}

func scan(start, stop int64, infile, savefile string) {
	var count = 0
	for i := start; i < stop; i++ {
		key, err := genkey(i)
		if err != nil {
			fmt.Println("[!] failed to generate key:", err.Error())
		}
		tmp, err := tmpFile()
		if err != nil {
			fmt.Println("[!] failed to generate temp file:", err.Error())
			os.Exit(1)
		}
		defer os.Remove(tmp)
		err = badcrypto.DecryptFile(infile, tmp, key)
		if err != nil {
			continue
		}
		fmt.Println("[+] key was generated with timestamp", i)
		if savefile != "" {
			outfile := fmt.Sprintf("%s.%d", savefile, i)
			err = badcrypto.DecryptFile(infile, outfile, key)
			if err != nil {
				fmt.Println("[!] failed to save decrypted file:", err.Error())
			}
		}

		keyfile := fmt.Sprintf("key-%d.out", i)
		err = ioutil.WriteFile(keyfile, key, 0644)
		if err != nil {
			fmt.Println("[!] failed to write key file:", err.Error())
		}
		os.Exit(0)
	}

	fmt.Println("[!] no key found -- try expanding the search")

	os.Exit(1)
}

func tmpFile() (name string, err error) {
	tmpf, err := ioutil.TempFile("", "thief")
	if err != nil {
		return
	}
	name = tmpf.Name()
	tmpf.Close()
	os.Remove(name)
	return
}
