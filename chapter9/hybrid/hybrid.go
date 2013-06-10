package hybrid

import (
	"crypto/rsa"
	"encoding/asn1"
	"github.com/kisom/gocrypto/chapter7/pkc"
	"github.com/kisom/gocrypto/chapter8/pks"
)

const (
	SymKeyLen = 16 // AES-128 key size
	MacKeyLen = 32 // HMAC-SHA256 key size
)

type Message struct {
	Key []byte
	Sig []byte
	Msg []byte
}

func generateSessionKeys(prv *rsa.PrivateKey) (key, sig []byte, err error) {
	var sym, mac []byte
	if sym, err = Random(SymKeyLen); err != nil {
		return
	} else if mac, err = Random(MacKeyLen); err != nil {
		return
	}

	key = make([]byte, SymKeyLen+MacKeyLen)
	copy(key, sym)
	copy(key[SymKeyLen:], mac)
	scrub(mac, 3)
	scrub(sym, 3)
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
	} else if msg.Msg, err = symEncrypt(key[:SymKeyLen], key[SymKeyLen:], m); err != nil {
		return
	}
	ct, err = asn1.Marshal(msg)
	scrub(key, 3)
	return
}

func readSessionKeys(prv *rsa.PrivateKey, pub *rsa.PublicKey, key, sig []byte) (sym, mac []byte, err error) {
	if key, err = pkc.Decrypt(prv, key); err != nil {
		return
	} else if len(key) != SymKeyLen+MacKeyLen {
		err = ErrInvalidKey
		return
	}

	err = pks.Verify(pub, key, sig)
	if err != nil {
		return
	}
	sym = key[:SymKeyLen]
	mac = key[SymKeyLen:]
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
	m, err = symDecrypt(sym, mac, msg.Msg)
	scrub(sym, 3)
	scrub(mac, 3)
	return
}
