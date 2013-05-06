package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
)

var password string
var errRegexp = regexp.MustCompile("^error: (.+)$")

func hash(data string) (h []byte) {
	c := sha256.New()
	c.Write([]byte(data))
	binHash := c.Sum(nil)

	h = make([]byte, 0)
	for _, b := range binHash {
		ch := fmt.Sprintf("%02x", b)
		h = append(h, []byte(ch)...)
	}
	return
}

func main() {
	var err error

	fAddress := flag.String("a", ":4141", "server address")
	fPass := flag.String("p", "", "server password")
	flag.Parse()
	password = *fPass
	if err != nil {
		fmt.Println("[!] couldn't read password:", err.Error())
		os.Exit(1)
	}
	connect(*fAddress)
}

func connect(address string) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("[!] failed to connect:", err.Error())
		os.Exit(1)
	}

	fmt.Println("[+] connected!")
	challenge := make([]byte, 64)
	n, err := conn.Read(challenge)
	if err != nil {
		fmt.Println("[!] error getting challenge from server:", err.Error())
		os.Exit(1)
	}
	challenge = challenge[:n]
	responseStr := fmt.Sprintf("%s%s", password, string(challenge))
	response := hash(responseStr)
	_, err = conn.Write(response)
	if err != nil {
		fmt.Println("[!] failed to send response:", err.Error())
		os.Exit(1)
	}

	response = make([]byte, 512)
	n, err = conn.Read(response)
	if err != nil {
		fmt.Println("[!] failed to receive response from server:", err.Error())
	}
	response = response[:n]
	if errRegexp.Match(response) {
		fmt.Printf("[!] %s\n", string(response))
	} else {
		fmt.Printf("[+] server response: %s\n", string(response))
	}
}
