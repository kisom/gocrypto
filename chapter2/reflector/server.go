package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
)

const (
	chatPort   = 4001
	msgBuf     = 16
	maxMsg     = 1024
	DateFormat = "2006-02-01 15:04:05"
)

var (
	Incoming = make(chan Transmit, msgBuf)
	Outgoing = make(chan []byte, msgBuf)
)

var config struct {
	User string
}

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

func main() {
	fUser := flag.String("u", "reflector", "user to broadcast as")
	flag.Parse()

	config.User = *fUser

	networkChat()
}

func networkChat() {
	gaddr, ifi := selectInterface()
	log.Println("listening on ", ifi.Name)
	log.Println("using multicast address ", gaddr.String())
	go transmit(gaddr)
	receive(gaddr, ifi)
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
	} else if M.Sender == config.User {
		return
	}

	if M.Encryption {
		if !M.Control {
			M.Text[24] += 1
		}
		Incoming <- Transmit{M.Text, false}
	}
	return
}

func EncodeMessage(msg []byte, control bool) (wire []byte, err error) {
	msg = bytes.TrimSpace(msg)
	M := new(Message)
	M.Encryption = true
	M.Sender = config.User
	M.Text = msg
	M.Control = control
	wire, err = json.Marshal(&M)
	return
}
