package chain

import (
	"bytes"
	"crypto/cipher"
	"io"
)

type CHAIN struct {
	state *state
	aead  cipher.AEAD
	ad    []byte
	buf   *bytes.Buffer

	// next writer layer
	w io.Writer
	// next reader layer
	r io.Reader
}
