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
	srvChal := make([]byte, hap.ResponseLength)
	n, err := conn.Read(srvChal)
	if err != nil {
		fmt.Println("[!] error reading challenge from client:", err.Error())
		return
	} else {
		srvChal = srvChal[:n]
	}

	srvResponse := hap.Response(password, string(srvChal))
	_, err = conn.Write([]byte(srvResponse))
	if err != nil {
		fmt.Println("[!] failed to send response:", err.Error())
		return
	}

	ok := make([]byte, 2)
	_, err = conn.Read(ok)
	if err != nil {
		fmt.Println("[!] failed to receive acknowledgement")
		return
	}

	challenge := hap.Challenge()
	_, err = conn.Write([]byte(challenge))
	if err != nil {
		fmt.Println("[!] error sending challenge:", err.Error())
		return
	}

	response := make([]byte, hap.ResponseLength)
	n, err = conn.Read(response)
	if err != nil {
		fmt.Println("[!] error reading response from client:", err.Error())
		return
	} else {
		response = response[:n]
	}

	if !hap.Validate(password, challenge, response) {
		fmt.Println("[!] client failed authentication")
		return
	}
	conn.Write([]byte("ok"))

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
