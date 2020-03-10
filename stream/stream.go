package stream

import (
	"bytes"
	"crypto/cipher"
	"io"
)

const (
	KeyLen  = 32
	SaltLen = 32
	SeedLen = 32
)

// an io.Reader implements Read()
// an io.Writer implements Write()

//
//
//
//
//
// THE NEW STREAM
//
//
//
//
//

type STREAM struct {
	aead cipher.AEAD // AEAD

	state *State // the state of the stream

	w io.Writer // writer
	r io.Reader // reader

	buffered int
	buf      *bytes.Buffer
}
