// client implements the client-side of the simple time server. it attempts
// to connect to the service.
package main

import (
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/symmetric"
	"io/ioutil"
	"net"
	"os"
)

var (
	Key     []byte
	Address string
)

func init() {
	keyFile := flag.String("k", "client.key", "server's key")
	port := flag.Int("p", 4141, "port to listen on")
	host := flag.String("a", "", "address to listen on")
	flag.Parse()
	Address = fmt.Sprintf("%s:%d", *host, *port)

	var err error
	Key, err = ioutil.ReadFile(*keyFile)
	if err != nil {
		panic(err.Error())
	}
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", Address)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("[+] dialing server: ", Address)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Printf("[!] couldn't connect to %s\n", Address)
		os.Exit(1)
	}

        fmt.Println("[+] waiting on challenge")
	nonce, err := ioutil.ReadAll(conn)
	if err != nil {
		fmt.Println("[!] error reading server's response")
		os.Exit(1)
	}

        fmt.Println("[+] received challenge from server")
        eNonce, err := symmetric.EncryptBytes(Key, nonce)
        if err != nil {
                fmt.Println("[!] error encrypting nonce: ", err.Error())
                os.Exit(1)
        }

        fmt.Println("[+] sending response")
        _, err = conn.Write(eNonce)
        if err != nil {
                fmt.Println("[!] error sending encrypted nonce: ", err.Error())
                os.Exit(1)
        }

        fmt.Println("waiting on secret")
        msg, err := ioutil.ReadAll(conn)
        if err != nil {
                fmt.Println("[!] error reading response: ", err.Error())
                os.Exit(1)
        }

        fmt.Println("[+] retrieved timestamp:")
        fmt.Println("    ", string(msg))
}
