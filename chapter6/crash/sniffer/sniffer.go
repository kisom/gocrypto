package main

import (
	"flag"
	"fmt"
	"github.com/akrennmair/gopcap"
	"os"
)

func main() {
	iface := flag.String("i", "lo", "interface to capture on")
	flag.Parse()

	capture, err := pcap.Openlive(*iface, 1600, true, 0)
	if err != nil {
		fmt.Println("[!] failed to start capture:", err.Error())
		os.Exit(1)
	}
	defer capture.Close()
}

