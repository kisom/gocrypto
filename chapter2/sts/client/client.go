package main

import (
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/symmetric"
	"io/ioutil"
        "net"
        "os"
        "strconv"
	"time"
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

func decryptTime(enc []byte) (ts string) {
        msg, err := symmetric.FromByte(enc).Decrypt(Key)
        if err != nil {
                panic(err.Error())
        }
        fmt.Printf("[+] decrypted message is %d bytes\n", len(msg))

        tsInt, err := strconv.ParseInt(string(msg), 10, 64)
        if err != nil {
                panic("error parsing time!")
        }
        ts = time.Unix(tsInt, 0).String()
        return
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

        msg, err := ioutil.ReadAll(conn)
        if err != nil {
                fmt.Println("[!] error reading server's response")
                os.Exit(1)
        }

        timeStamp := decryptTime(msg)
        fmt.Println("[+] retrieved time:");
        fmt.Println("    ", timeStamp)
}


