package pkc

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type PubKey struct {
	Id  string
	Key *rsa.PublicKey
}

type KeyChain struct {
	Private *rsa.PrivateKey
	Public  []*PubKey
}

var ErrInvalidKeyChain = fmt.Errorf("invalid keychain")

func NewKeyChain(prv *rsa.PrivateKey) (kc *KeyChain, err error) {
	if err = prv.Validate(); err != nil {
		return
	}
	kc = new(KeyChain)
	kc.Private = prv
	kc.Public = make([]*PubKey, 0)
	return
}

func ImportKeyChain(filename string) (kc *KeyChain, err error) {
	var keychain KeyChain
	pubs := make([]*PubKey, 0)

	in, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	for {
		var blk *pem.Block
		blk, in = pem.Decode(in)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "RSA PRIVATE KEY":
			if keychain.Private != nil {
				err = ErrInvalidKeyChain
				return
			}
			keychain.Private, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
			if err != nil {
				err = ErrInvalidKeyChain
				return
			}
		case "RSA PUBLIC KEY":
			var inpub interface{}
			inpub, err = x509.ParsePKIXPublicKey(blk.Bytes)
			if err != nil {
				return
			}

			pubs = append(pubs, &PubKey{blk.Headers["id"], inpub.(*rsa.PublicKey)})
		}
		if in == nil || len(in) == 0 {
			break
		}
	}
	if err == nil {
		keychain.Public = pubs
		kc = &keychain
	}
	return
}

func (kc *KeyChain) AddPublic(id string, pub *rsa.PublicKey) {
	if pub == nil {
		return
	}
	for _, pk := range kc.Public {
		if pk.Id == id {
			pk.Key = pub
			return
		}
	}
	kc.Public = append(kc.Public, &PubKey{id, pub})
}

func (kc *KeyChain) GetPublic(id string) (pub *rsa.PublicKey) {
	for _, pk := range kc.Public {
		if pk.Id == id {
			pub = pk.Key
			return
		}
	}
	return
}

func (kc *KeyChain) RemovePublic(id string) bool {
	for i, pk := range kc.Public {
		if pk.Id == id {
			kc.Public = append(kc.Public[:i], kc.Public[i+1:]...)
			return true
		}
	}
	return false
}

func (kc *KeyChain) Validate() bool {
	if kc == nil {
		return false
	} else if kc.Private == nil {
		return false
	} else if err := kc.Private.Validate(); err != nil {
		return false
	} else if kc.Public == nil {
		return false
	}
	return true
}

func (kc *KeyChain) Export(filename string) (err error) {
	if !kc.Validate() {
		return ErrInvalidKeyChain
	}

	var blk pem.Block
	var buf = new(bytes.Buffer)
	var fail = func() {
		buf.Reset()
		err = ErrInvalidKeyChain
	}

	blk.Type = "RSA PRIVATE KEY"
	blk.Bytes = x509.MarshalPKCS1PrivateKey(kc.Private)
	err = pem.Encode(buf, &blk)
	if err != nil {
		fail()
		return
	}

	blk.Type = "RSA PUBLIC KEY"
	for _, pk := range kc.Public {
		if pk.Key == nil {
			continue
		}
		if pk.Id != "" {
			if blk.Headers == nil {
				blk.Headers = make(map[string]string)
			}
			blk.Headers["id"] = pk.Id
		} else {
			if blk.Headers != nil {
				delete(blk.Headers, "id")
				blk.Headers = nil
			}
		}
		blk.Bytes, err = x509.MarshalPKIXPublicKey(pk.Key)
		if err != nil {
			fail()
			return
		}
		err = pem.Encode(buf, &blk)
		if err != nil {
			fail()
		}
	}
	err = ioutil.WriteFile(filename, buf.Bytes(), 0400)
	buf.Reset()
	return
}
