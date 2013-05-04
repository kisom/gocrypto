package main

import (
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter5/hap"
	"net"
	"os"
)

var password string

func authenticate(conn net.Conn) (authenticated bool) {
	err := hap.Authenticate(conn, password)
	if err != nil {
		fmt.Println("[!] failed to authenticate:", err.Error())
		return
	}

	err = hap.Challenge(conn, password)
	if err != nil {
		fmt.Println("[!] challenge failed:", err.Error())
		return
	}

	authenticated = true
	return
}

func main() {
	var address string

	fPass := flag.String("p", "", "authentication password")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("[!] no server specified")
		os.Exit(1)
	} else if *fPass == "" {
		fmt.Println("[!] no password specified")
		os.Exit(1)
	} else {
		address = flag.Args()[0]
		password = *fPass
	}

	fmt.Println("[+] connecting to", address)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("[!] connect failed:", err.Error())
		os.Exit(1)
	}
	defer conn.Close()

	if !authenticate(conn) {
		fmt.Println("[!] authentication failed")
	} else {
		fmt.Println("[+] sending request")
		_, err = conn.Write([]byte("foo"))
		if err != nil {
			fmt.Println("[!] failed to send request:", err.Error())
			return
		}
		fmt.Println("[+] successfully made request")
	}

}
