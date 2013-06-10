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

func generateEphemeralKeys(prv *rsa.PrivateKey) (key, sig []byte, err error) {
        var sym, mac []byte
	if sym, err = Random(SymKeyLen); err != nil {
		return
	} else if kex.Mac, err = Random(MacKeyLen); err != nil {
		return
	}

	key = make([]byte, SymKeyLen+MacKeyLen)
	copy(key, sym)
	copy(key[SymKeyLen:], mac)
	sig, err = pks.Sign(prv, key)
	return
}

func Encrypt(prv *rsa.PrivateKey, pub *rsa.PublicKey, m []byte) (ct []byte, err error) {
	var msg Message
	var kex KeyExchange
	if kex, msg.Sig, err = generateEphemeralKeys(prv); err != nil {
		return
	}

	var kexEncoded []byte
	if kexEncoded, err = asn1.Marshal(kex); err != nil {
		return
	}

	if msg.Key, err = pkc.Encrypt(pub, kexEncoded); err != nil {
		return
	} else if msg.Msg, err = symEncrypt(kex.Sym, kex.Mac, m); err != nil {
		return
	}
	ct, err = asn1.Marshal(msg)
	scrub(kex.Sym, 3)
	scrub(kex.Mac, 3)
	scrub(kexEncoded, 3)
	return
}

func readEphemeralKeys(prv *rsa.PrivateKey, pub *rsa.PublicKey, key, sig []byte) (sym, mac []byte, err error) {
	var kex KeyExchange
	if key, err = pkc.Decrypt(prv, key); err != nil {
		return
	}

	err = pks.Verify(pub, key, sig)
	scrub(key, 3)
	if err != nil {
		return
	}
	return key[:SymKeyLen], key[SymKeyLen:], nil
}

func Decrypt(prv *rsa.PrivateKey, pub *rsa.PublicKey, ct []byte) (m []byte, err error) {
	var msg Message

	if _, err = asn1.Unmarshal(ct, &msg); err != nil {
		return
	}

	var sym, mac []byte
	sym, mac, err = readEphemeralKeys(prv, pub, msg.Key, msg.Sig)
	if err != nil {
		return
	}
	m, err = symDecrypt(sym, mac, msg.Msg)
	scrub(sym, 3)
	scrub(mac, 3)
	return
}
