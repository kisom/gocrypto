package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/go.net/websocket"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/kisom/gocrypto/chapter2/salsa20"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"
)

const (
	chatPort   = 4001
	msgBuf     = 16
	maxMsg     = 1024
	DateFormat = "2006-02-01 15:04:05"
)

var config struct {
	User string
	Port string
	Key  *[salsa20.KeySize]byte
}

var (
	Incoming = make(chan Transmit, msgBuf)
	Outgoing = make(chan []byte, msgBuf)
)

type Message struct {
	Sender     string
	Text       []byte
	Encryption bool
	Control    bool
}

type Transmit struct {
	Data    []byte
	Control bool
}

func transmitterHandler(ws *websocket.Conn) {
	log.Println("client connected.")
	Incoming <- Transmit{[]byte("is online"), true}
	buf := bufio.NewReader(ws)
	for {
		msg, err := buf.ReadBytes('\n')
		if err == io.EOF {
			log.Println("client disconnected.")
			break
		} else if err != nil {
			log.Println("error reading from websocket: ", err.Error())
			continue
		}
		Incoming <- Transmit{msg, false}
	}
	Incoming <- Transmit{[]byte("is offline"), true}

}

func receiverHandler(ws *websocket.Conn) {
	messages := make([][]byte, 0)
	msgCount := len(Outgoing)
	if msgCount == 0 {
		return
	}
	for i := 0; i < msgCount; i++ {
		messages = append(messages, <-Outgoing)
	}

	wire, err := json.Marshal(messages)
	if err != nil {
		ws.Close()
	}
	ws.Write(wire)
}

func main() {
	fKeyFile := flag.String("k", "", "key file")
	fPort := flag.Int("p", 4000, "listening port")
	fUser := flag.String("u", "anonymous", "user to broadcast as")
	flag.Parse()

	config.Port = fmt.Sprintf("%d", *fPort)
	config.User = *fUser

	if *fKeyFile != "" {
		var err error
		config.Key, err = ReadKeyFromFile(*fKeyFile)
		if err != nil {
			log.Fatalf("[!] failed to load %s: %s\n", *fKeyFile,
				err.Error())
		}
	}

	go networkChat()
	http.HandleFunc("/", rootHandler)
	http.Handle("/socket", websocket.Handler(transmitterHandler))
	http.Handle("/incoming", websocket.Handler(receiverHandler))
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

func networkChat() {
	gaddr, ifi := selectInterface()
	log.Println("listening on ", ifi.Name)
	log.Println("using multicast address ", gaddr.String())
	go transmit(gaddr)
	go receive(gaddr, ifi)
}

func transmit(gaddr *net.UDPAddr) {
	for {
		msg, ok := <-Incoming
		if !ok {
			log.Println("transmit channel closed")
			return
		}
		broadcast, err := EncodeMessage(msg.Data, msg.Control)
		if err != nil {
			log.Println("failed to encode message: ", err.Error())
			continue
		}
		uc, err := net.DialUDP("udp", nil, gaddr)
		if err != nil {
			log.Println("failed to dial multicast: ", err.Error())
			continue
		}
		_, err = uc.Write(broadcast)
		if err != nil {
			log.Println("failed to send message: ", err.Error())
			continue
		}
	}
}

func receive(gaddr *net.UDPAddr, ifi *net.Interface) {
	for {
		uc, err := net.ListenMulticastUDP("udp", ifi, gaddr)
		if err != nil {
			log.Fatal("failed to set up multicast listener: ",
				err.Error())
		}
		msg := make([]byte, maxMsg)
		n, _, err := uc.ReadFrom(msg)
		if err != nil {
			log.Println("error reading incoming message: ", err.Error())
			continue
		} else if n == 0 {
			continue
		}
		out, err := DecodeMessage(msg[:n])
		if err != nil {
			log.Println("failed to decode message: ", err.Error())
			log.Printf("msg: %s\n\t%+v", string(msg), msg)
			continue
		}
		Outgoing <- []byte(out)
	}
}

func parseAddr(addr string) *net.IP {
	ipAddr, _, err := net.ParseCIDR(addr)
	if err != nil {
		ipAddr = net.ParseIP(addr)
	}
	if ipAddr == nil {
		return nil
	}
	return &ipAddr
}

func selectInterface() (*net.UDPAddr, *net.Interface) {
	var netInterface *net.Interface
	var loopback = regexp.MustCompile("^lo")

	interfaceList, err := net.Interfaces()
	if err != nil {
		fmt.Println("[!] couldn't load interface list: ", err.Error())
		os.Exit(1)
	}

	for _, ifi := range interfaceList {
		if loopback.MatchString(ifi.Name) {
			continue
		}
		addrList, err := ifi.Addrs()
		if err != nil {
			fmt.Println("[!] couldn't load interface list: ",
				err.Error())
			os.Exit(1)
		}
		for _, addr := range addrList {
			ip := parseAddr(addr.String())
			if !ip.IsLoopback() {
				netInterface = &ifi
				break
			}
		}
		if netInterface != nil {
			break
		}
	}

	if netInterface == nil {
		fmt.Println("[!] couldn't find a valid interface")
		os.Exit(1)
	}

	chatSvc := fmt.Sprintf("239.255.255.250:%d", chatPort)
	gaddr, err := net.ResolveUDPAddr("udp", chatSvc)

	if err != nil {
		fmt.Println("[!] couldn't resolve multicast address: ", err.Error())
		os.Exit(1)
	}

	return gaddr, netInterface
}

func DecodeMessage(msg []byte) (msgStr string, err error) {
	M := new(Message)
	err = json.Unmarshal(msg, &M)
	if err != nil {
		return
	}

	if M.Encryption {
		if !M.Control && config.Key != nil {
			tmp, ok := salsa20.Decrypt(config.Key, M.Text)
			if ok {
				M.Text = tmp
			} else {
				M.Text = []byte(ShowError("[decryption error]"))
			}
			err = nil
		} else if !M.Control {
			M.Text = []byte(ShowError("[no secret key]"))
		}

		M.Text = []byte(fmt.Sprintf("%s %s", ShowSuccess("[encrypted]"),
			string(M.Text)))
	}

	if !M.Control {
		msgStr = fmt.Sprintf("<%s> %s: %s\n", time.Now().Format(DateFormat),
			M.Sender, string(M.Text))
	} else {
		msgStr = fmt.Sprintf("<%s> %s %s\n", time.Now().Format(DateFormat),
			M.Sender, string(M.Text))
		msgStr = ShowControl(msgStr)
	}
	return
}

func EncodeMessage(msg []byte, control bool) (wire []byte, err error) {
	msg = bytes.TrimSpace(msg)
	M := new(Message)
	if !control && config.Key != nil {
		msg = salsa20.Encrypt(config.Key, msg)
		M.Encryption = true
	}
	M.Sender = config.User
	M.Text = msg
	M.Control = control
	wire, err = json.Marshal(&M)
	return
}

// Read a key from a file
func ReadKeyFromFile(filename string) (*[salsa20.KeySize]byte, error) {
	var key [salsa20.KeySize]byte
	keyFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	_, err = keyFile.Read(key[:])
	keyFile.Close()
	if err != nil {
		return nil, err
	}

	return &key, nil
}
