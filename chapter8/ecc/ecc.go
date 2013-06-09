package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

var DefaultCurve = elliptic.P256()

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func GenerateKey() (prv *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(DefaultCurve, rand.Reader)
}

func Sign(prv *ecdsa.PrivateKey, m []byte) (sig []byte, err error) {
	h := sha256.New()
	h.Write(m)
	d := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, prv, d)
	if err != nil {
		return
	}
	sig, err = asn1.Marshal(ECDSASignature{r, s})
	return
}

func Verify(pub *ecdsa.PublicKey, m, sig []byte) bool {
	var asnSig ECDSASignature
	_, err := asn1.Unmarshal(sig, &asnSig)
	if err != nil {
		return false
	}
	h := sha256.New()
	h.Write(m)
	d := h.Sum(nil)
	return ecdsa.Verify(pub, d, asnSig.R, asnSig.S)
}
