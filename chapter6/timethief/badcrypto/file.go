package badcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"os"
)

const ReadSize = 4096

// Encrypt an io.Reader to an io.Writer
func EncryptReader(key []byte, r io.Reader, w io.Writer) (err error) {
	h := hmac.New(sha256.New, key)
	iv, err := GenerateIV()
	if err != nil {
		return
	}
	_, err = w.Write(iv)
	if err != nil {
		return
	} else if _, err = h.Write(iv); err != nil {
		return
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(aes, iv)
	for {
		var n int
		block := make([]byte, ReadSize)
		n, err = r.Read(block)
		if err != nil {
			break
		}
		block = block[:n]
		ctr.XORKeyStream(block, block)
		if _, err = h.Write(block); err != nil {
			return
		} else if _, err = w.Write(block); err != nil {
			return
		}
	}
	digest := h.Sum(nil)
	_, err = w.Write(digest)
	return
}

// Decrypt an io.Reader to an io.Writer.
func DecryptReader(key []byte, r io.Reader, w io.Writer, size int64) (err error) {
	var count int64
	h := hmac.New(sha256.New, key)
	aes, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv := make([]byte, BlockSize)
	if _, err = io.ReadFull(r, iv); err != nil {
		return
	} else if _, err = h.Write(iv); err != nil {
		return
	}
	count += BlockSize
	ctr := cipher.NewCTR(aes, iv)
	for {
		var n, readSize int

		if (size - count) > int64(ReadSize) {
			readSize = ReadSize
		} else {
			readSize = int(size - count)
		}
		block := make([]byte, readSize)
		if n, err = r.Read(block); err != nil {
			return
		} else {
			block = block[:n]
		}

		h.Write(block)
		ctr.XORKeyStream(block, block)
		if _, err = w.Write(block); err != nil {
			return
		}
		count += int64(n)
		if count == size {
			break
		}
	}
	hSum := h.Sum(nil)
	digest := make([]byte, sha256.Size)
	if _, err = r.Read(digest); err != nil {
		return
	} else if !bytes.Equal(hSum, digest) {
		err = BadDecryptionError
	}
	return
}

// Encrypt the input file to the output file.
func EncryptFile(in, out string, key []byte) (err error) {
	inFile, err := os.Open(in)
	if err != nil {
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer outFile.Close()

	err = EncryptReader(key, inFile, outFile)
	return
}

// Decrypt the input file to the output file.
func DecryptFile(in, out string, key []byte) (err error) {
	inFile, err := os.Open(in)
	if err != nil {
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600)
	if err != nil {
		return
	}
	defer outFile.Close()

	fi, err := inFile.Stat()
	if err != nil {
		return
	}

	readLen := fi.Size() - int64(sha256.Size)
	err = DecryptReader(key, inFile, outFile, readLen)
	return
}
