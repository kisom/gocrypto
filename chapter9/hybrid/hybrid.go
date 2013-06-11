package hybrid

import (
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"github.com/kisom/gocrypto/chapter7/pkc"
	"github.com/kisom/gocrypto/chapter8/pks"
	"github.com/kisom/gocrypto/chapter9/authsym"
)

var ErrInvalidKey = fmt.Errorf("hybrid: invalid key")
var SharedKeyLen = authsym.SymKeyLen + authsym.MacKeyLen

type Message struct {
	Key []byte
	Sig []byte
	Msg []byte
}

func generateSessionKeys(prv *rsa.PrivateKey) (key, sig []byte, err error) {
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
	sig, err = pks.Sign(prv, key)
	return
}

func Encrypt(prv *rsa.PrivateKey, pub *rsa.PublicKey, m []byte) (ct []byte, err error) {
	var msg Message
	var key []byte
	if key, msg.Sig, err = generateSessionKeys(prv); err != nil {
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

func readSessionKeys(prv *rsa.PrivateKey, pub *rsa.PublicKey, key, sig []byte) (sym, mac []byte, err error) {
	if key, err = pkc.Decrypt(prv, key); err != nil {
		return
	} else if len(key) != authsym.SymKeyLen+authsym.MacKeyLen {
		err = ErrInvalidKey
		return
	}

	err = pks.Verify(pub, key, sig)
	if err != nil {
		return
	}
	sym = key[:authsym.SymKeyLen]
	mac = key[authsym.SymKeyLen:]
	return
}

func Decrypt(prv *rsa.PrivateKey, pub *rsa.PublicKey, ct []byte) (m []byte, err error) {
	var msg Message

	if _, err = asn1.Unmarshal(ct, &msg); err != nil {
		return
	}

	sym, mac, err := readSessionKeys(prv, pub, msg.Key, msg.Sig)
	if err != nil {
		return
	}
	m, err = authsym.Decrypt(sym, mac, msg.Msg)
	authsym.Scrub(sym, 3)
	authsym.Scrub(mac, 3)
	return
}
