package armour

import "encoding/base64"
import "io"

// Encoding selects the base64 encoding scheme to use. The default is
// the standard RFC 4686 encoding scheme. This can be used, for example,
// to use base64.URLEncoding in the functions instead.
var Encoding = base64.StdEncoding

// EncodeBase64 takes binary data as input and outputs a base64'd string.
// It uses the standard RFC 4686 base64 encoding.
func EncodeBase64(data []byte) (out []byte) {
	out = make([]byte, Encoding.EncodedLen(len(data)))
	Encoding.Encode(out, data)
	return
}

// DecodeBase64 takes an RFC 4686 base64-encoded and outputs the decoded
// binary data. If an error occurs during the decoding (i.e., invalid
// base64 data), it will be returned.
func DecodeBase64(encoded []byte) (out []byte, err error) {
	out = make([]byte, Encoding.DecodedLen(len(encoded)))
	_, err = Encoding.Decode(out, encoded)
	return
}

// EncodeBase64Reader encodes binary data from an io.Reader and writes
// the data to an io.Writer. If an error occurs during the copy, it
// will be returned.
func EncodeBase64Reader(out io.Writer, src io.Reader) (err error) {
	encoder := base64.NewEncoder(Encoding, out)
	_, err = io.Copy(encoder, src)
	encoder.Close()
	return
}

// DecodeBase64Reader decodes base64-encoded data from an io.Reader
// to an io.Writer. If an error occurs during the copy, it will be
// returned.
func DecodeBase64Reader(out io.Writer, src io.Reader) (err error) {
        decoder := base64.NewDecoder(Encoding, src)
        _, err = io.Copy(out, decoder)
        return
}
