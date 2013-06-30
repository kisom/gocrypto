package hybrid

import (
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"github.com/kisom/gocrypto/chapter7/pkc"
	"github.com/kisom/gocrypto/chapter9/authsym"
)

var ErrInvalidKey = fmt.Errorf("hybrid: invalid key")
var SharedKeyLen = authsym.SymKeyLen + authsym.MacKeyLen

type Message struct {
	Key []byte
	Msg []byte
}

func generateSessionKeys() (key []byte, err error) {
	var sym, mac []byte
	if sym, err = authsym.GenerateAESKey(); err != nil {
		return
	} else if mac, err = authsym.GenerateHMACKey(); err != nil {
		return
	}

	key = make([]byte, SharedKeyLen)
	copy(key, sym)
	copy(key[authsym.SymKeyLen:], mac)
	authsym.Scrub(mac, 3)
	authsym.Scrub(sym, 3)
	return
}

func Encrypt(pub *rsa.PublicKey, m []byte) (ct []byte, err error) {
	var msg Message
	var key []byte

	key, err = generateSessionKeys()
	if err != nil {
		return
	}
	if msg.Key, err = pkc.Encrypt(pub, key); err != nil {
		return
	} else if msg.Msg, err = authsym.Encrypt(key[:authsym.SymKeyLen], key[authsym.SymKeyLen:], m); err != nil {
		return
	}
	ct, err = asn1.Marshal(msg)
	authsym.Scrub(key, 3)
	return
}

func readSessionKeys(prv *rsa.PrivateKey, key []byte) (sym, mac []byte, err error) {
	if key, err = pkc.Decrypt(prv, key); err != nil {
		return
	} else if len(key) != authsym.SymKeyLen+authsym.MacKeyLen {
		err = ErrInvalidKey
		return
	}

	sym = key[:authsym.SymKeyLen]
	mac = key[authsym.SymKeyLen:]
	return
}

func Decrypt(prv *rsa.PrivateKey, ct []byte) (m []byte, err error) {
	var msg Message

	if _, err = asn1.Unmarshal(ct, &msg); err != nil {
		return
	}

	sym, mac, err := readSessionKeys(prv, msg.Key)
	if err != nil {
		return
	}
	m, err = authsym.Decrypt(sym, mac, msg.Msg)
	authsym.Scrub(sym, 3)
	authsym.Scrub(mac, 3)
	return
}
