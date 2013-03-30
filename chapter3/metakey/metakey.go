package metakey

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/gokyle/tlv"
	"github.com/kisom/gocrypto/chapter3/armour"
	"io"
	"io/ioutil"
	"os"
	"time"
)

const (
	AES128KeyLength = 16
	AES192KeyLength = 24
	AES256KeyLength = 32
)

// These constants are used to select which encryption algorithm to use.
const (
	AES128 = iota
	AES192
	AES256
)

const (
	tagDescription = iota
	tagExpiration
	tagKeyAES128
	tagKeyAES192
	tagKeyAES256
)

var (
	ErrInvalidKey          = fmt.Errorf("invalid key")
	ErrKeySizeNotSupported = fmt.Errorf("key size is not supported")
)

// Type MetaKey represents a key with additional metadata attached.
// Specifically, it provide three keys (for AES128, AES192, and AES256),
// a description field, and an expiration timestamp. Once created, its
// fields cannot be changed in code.
type MetaKey struct {
	fields *tlv.TLVList
}

// New creates a new MetaKey with the provided expiration timestamp
// and description. Note that it generates all of the required keys.
func New(descr string, expires int64) (mk *MetaKey, err error) {
	mk = new(MetaKey)

	t := time.Unix(expires, 0)

	mk.fields = tlv.New()
	mk.fields.Add(tagDescription, []byte(descr))
	mk.fields.Add(tagExpiration, []byte(t.String()))

	key, err := newBinaryKey(AES128KeyLength)
	if err != nil {
		return
	}
	mk.fields.Add(tagKeyAES128, key)

	key, err = newBinaryKey(AES192KeyLength)
	if err != nil {
		return
	}
	mk.fields.Add(tagKeyAES192, key)

	key, err = newBinaryKey(AES256KeyLength)
	if err != nil {
		return
	}
	mk.fields.Add(tagKeyAES256, key)
	return
}

// Description returns the key's description as a string.
func (mk *MetaKey) Description() (d string, err error) {
	tlv, err := mk.fields.Get(tagDescription)
	if tlv != nil {
		d = string(tlv.Value())
	}
	return
}

// Expires returns the expiration date as an ANSIC-formatted string.
func (mk *MetaKey) Expires() (e string, err error) {
	tlv, err := mk.fields.Get(tagExpiration)
	if tlv != nil {
		e = string(tlv.Value())
	}
	return
}

// ExpireStamp returns the expiration date as a Unix timestamp.
func (mk *MetaKey) ExpireStamp() (t int64, err error) {
	e, err := mk.Expires()
	if err != nil {
		return
	}
	tm, err := time.Parse(time.ANSIC, e)
	if err != nil {
		return
	}
	t = tm.Unix()
	return
}

// IsExpired returns true if the key is expired, and false if not.
func (mk *MetaKey) IsExpired() bool {
	e, err := mk.Expires()
	if err != nil {
		return true
	}

	t, err := mk.ExpireStamp()
	if err != nil {
		return true
	} else if t == 0 {
		return false
	}

	tm, err := time.Parse(time.ANSIC, e)
	if err != nil {
		return true
	}
	return tm.After(time.Now())
}

// GetKey returns the appropriate encryption key for the requested algorithm.
func (mk *MetaKey) GetKey(keySize int) (key []byte, err error) {
	var keyType int
	var supported bool

	switch keySize {
	case AES128KeyLength:
		supported = true
		keyType = tagKeyAES128
	case AES192KeyLength:
		supported = true
		keyType = tagKeyAES192
	case AES256KeyLength:
		supported = true
		keyType = tagKeyAES256
	default:
		supported = false
	}
	if !supported {
		return key, ErrKeySizeNotSupported
	}
	tlv, err := mk.fields.Get(keyType)
	if err != nil {
		return
	}
	key = tlv.Value()
	return
}

func (mk *MetaKey) Encrypt(algo int, msg []byte, armoured bool) (ct []byte, err error) {
	var keySize int
	switch algo {
	case AES128:
		keySize = AES128KeyLength
	case AES192:
		keySize = AES192KeyLength
	case AES256:
		keySize = AES256KeyLength
	default:
		return ct, ErrKeySizeNotSupported
	}

	key, err := mk.GetKey(keySize)
	if err != nil {
		return
	}

	return armour.Encrypt(key, msg, armoured)
}

func (mk *MetaKey) Decrypt(algo int, ct []byte) (pt []byte, err error) {
	var keySize int
	switch algo {
	case AES128:
		keySize = AES128KeyLength
	case AES192:
		keySize = AES192KeyLength
	case AES256:
		keySize = AES256KeyLength
	default:
		return ct, ErrKeySizeNotSupported
	}

	key, err := mk.GetKey(keySize)
	if err != nil {
		return
	}

	return armour.Decrypt(key, ct)
}

func (mk *MetaKey) WriteFile(filename string) (err error) {
	buf := new(bytes.Buffer)
	if err = mk.fields.Write(buf); err != nil {
		return
	}

	return ioutil.WriteFile(filename, buf.Bytes(), 0644)
}

func (mk *MetaKey) Write(w io.Writer) (err error) {
	return mk.fields.Write(w)
}

func Read(r io.Reader) (mk *MetaKey, err error) {
	mk = new(MetaKey)
	mk.fields, err = tlv.Read(r)
	return
}

func ReadFile(filename string) (mk *MetaKey, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	return Read(file)
}

func (mk *MetaKey) Export(filename string) (err error) {
	buf := new(bytes.Buffer)
	err = mk.Write(buf)
	if err != nil {
		return
	}

	out := armour.EncodeBase64(buf.Bytes())
	err = ioutil.WriteFile(filename, out, 0644)
	return
}

func Import(filename string) (mk *MetaKey, err error) {
	in, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	in, err = armour.DecodeBase64(in)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(in)
	mk, err = Read(buf)
	return
}

func (mk *MetaKey) Valid() bool {
	_, err := mk.fields.Get(tagDescription)
	if err != nil {
		fmt.Printf("tagDescription: %s\n", err.Error())
		return false
	}
	_, err = mk.fields.Get(tagExpiration)
	if err != nil {
		fmt.Printf("tagExpiration: %s\n", err.Error())
		return false
	}
	validKeySizes := []int{AES128KeyLength, AES192KeyLength, AES256KeyLength}
	for _, size := range validKeySizes {
		key, err := mk.GetKey(size)
		if err != nil || len(key) != (size+1) {
			return false
		}
	}

	return true
}

func newBinaryKey(size int) (key []byte, err error) {
	var n int

	key = make([]byte, size+1)
	key[0] = 0
	if n, err = rand.Read(key[1:]); err != nil {
		return
	} else if n != size {
		return key, ErrInvalidKey
	}
	return
}
