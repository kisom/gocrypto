package main

import (
	"database/sql"
	"flag"
	"fmt"
	"github.com/akrennmair/gopcap"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"os/signal"
	"syscall"
)

type Host struct {
	IP   string
	Port uint16
}

func (host *Host) String() string {
	return fmt.Sprintf("%s:%d", host.IP, host.Port)
}

type Conversation struct {
	Server *Host
	Client *Host
	CR     *ChalResp
}

func (c Conversation) MatchHosts(srv, cli *Host) bool {
	if c.Server.String() != srv.String() {
		return false
	} else if c.Client.String() != cli.String() {
		return false
	}
	return true
}

type ChalResp struct {
	Challenge []byte
	Response  []byte
}

func (cr *ChalResp) String() string {
	return fmt.Sprintf("%s:%x", string(cr.Challenge),
		cr.Response)
}

var (
	Conversations map[string]*Conversation
	ServerPort    uint16
	dbFile        = "challenges.db"
)

func init() {
	tables := make(map[string]string, 0)
	tables["challenges"] = `CREATE TABLE challenges
                (id integer primary key,
                 server text,
                 challenge blob,
                 response blob)`
	dbSetup(tables)
}

func main() {
	iface := flag.String("i", "lo", "interface to capture on")
	port := flag.Uint("p", 4141, "port CRA server listens on")
	flag.Parse()

	ServerPort = uint16(*port)
	filter := fmt.Sprintf("tcp port %d", ServerPort)

	capture, err := pcap.Openlive(*iface, 1600, true, 0)
	if err != nil {
		fmt.Println("[!] failed to start capture:", err.Error())
		os.Exit(1)
	}
	capture.Setfilter(filter)
	defer capture.Close()
	go listener(capture)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Kill, os.Interrupt, syscall.SIGTERM)
	<-sigc
	fmt.Println("shutting down.")
}

func listener(capture *pcap.Pcap) {
	Conversations = make(map[string]*Conversation, 0)
	for {
		pkt := capture.Next()
		if pkt == nil {
			continue
		}
		pkt.Decode()
		packetScanner(pkt)
	}
}

func packetScanner(pkt *pcap.Packet) {
	if startsConversation(pkt) {
		server := destHost(pkt)
		client := srcHost(pkt)
		Conversations[client.String()] =
			&Conversation{
				Server: server,
				Client: client,
				CR:     new(ChalResp),
			}
	} else if isDataPacket(pkt) {
		updateCR(pkt)
	}
}

func startsConversation(pkt *pcap.Packet) bool {
	return pkt.TCP.Flags == 2
}

func isDataPacket(pkt *pcap.Packet) bool {
	return pkt.TCP.Flags == 0x18
}

func destHost(pkt *pcap.Packet) *Host {
	host := new(Host)
	host.IP = pkt.IP.DestAddr()
	host.Port = pkt.TCP.DestPort
	return host
}

func srcHost(pkt *pcap.Packet) *Host {
	host := new(Host)
	host.IP = pkt.IP.SrcAddr()
	host.Port = pkt.TCP.SrcPort
	return host
}

func updateCR(pkt *pcap.Packet) {
	src := srcHost(pkt)
	dst := destHost(pkt)
	if src.Port == ServerPort {
		addChallenge(src, dst, pkt.Payload)
	} else {
		addResponse(src, dst, pkt.Payload)
	}
}

func addChallenge(srv *Host, cli *Host, challenge []byte) {
	for _, convo := range Conversations {
		if convo.MatchHosts(srv, cli) {
			convo.CR.Challenge = challenge[:]
			return
		}
	}
}

func addResponse(cli *Host, srv *Host, response []byte) {
	for k, convo := range Conversations {
		if convo.MatchHosts(srv, cli) {
			convo.CR.Response = response[:]
			go storeCR(convo)
			delete(Conversations, k)
		}
	}

}

func seenConversation(srv *Host, CR *ChalResp) bool {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		fmt.Println("[!] failed to open DB file:", err.Error())
		os.Exit(1)
	}
	defer db.Close()

	row := db.QueryRow(`select count(*) from challenges where
                server=? and challenge=? and response=?`, srv.String(),
		CR.Challenge, CR.Response)
	var count int
	err = row.Scan(&count)
	if err != nil {
		fmt.Println("[!] error querying database:", err.Error())
		os.Exit(1)
	}

	return count == 1
}

func storeCR(convo *Conversation) (err error) {
	if seenConversation(convo.Server, convo.CR) {
		fmt.Println("[+] found reused challenge",
			string(convo.CR.Challenge))
		return
	}
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		fmt.Println("[!] failed to open DB file:", err.Error())
		os.Exit(1)
	}
	defer db.Close()

	_, err = db.Exec(`insert into challenges
                (server, challenge, response) values
                (?, ?, ?)`, convo.Server.String(),
		convo.CR.Challenge, convo.CR.Response)
	if err != nil {
		fmt.Println("[!] failed to store challenge / response:",
			err.Error())
		os.Exit(1)
	}
	fmt.Println("[+] stored challenge", string(convo.CR.Challenge))
	return
}

func dbSetup(tables map[string]string) {
	fmt.Println("[+] checking tables")
	for tableName, tableSQL := range tables {
		fmt.Printf("\t[*] table %s\n", tableName)
		checkTable(tableName, tableSQL)
	}
	fmt.Println("[+] finished checking database")
}

func checkTable(tableName, tableSQL string) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		fmt.Println("[!] failed to open DB file:", err.Error())
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(`select sql from sqlite_master
                               where type='table' and name=?`, tableName)
	if err != nil {
		fmt.Println("[!] error looking up table:", err.Error())
		os.Exit(1)
	}

	var tblSql string
	for rows.Next() {
		err = rows.Scan(&tblSql)
		break
	}
	rows.Close()

	if err != nil {
		fmt.Println("[!] error reading database:", err.Error())
		os.Exit(1)
	} else if tblSql == "" {
		fmt.Println("\t\t[+] creating table")
		_, err = db.Exec(tableSQL)
		if err != nil {
			fmt.Println("[!] error creating table:", err.Error())
			os.Exit(1)
		}
	} else if tblSql != tableSQL {
		fmt.Println("\t\t[+] schema out of sync")
		_, err = db.Exec("drop table " + tableName)
		if err != nil {
			fmt.Println("[!] error dropping table:", err.Error())
			os.Exit(1)
		}
		_, err = db.Exec(tableSQL)
		if err != nil {
			fmt.Println("[!] error creating table:", err.Error())
			os.Exit(1)
		}
		fmt.Printf("\t[+] table %s updated\n", tableName)
	}
}
