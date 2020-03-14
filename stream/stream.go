package stream

import (
	"bytes"
	"crypto/cipher"
	"io"
)

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

	state *state // the state of the stream

	w io.Writer // writer
	r io.Reader // reader

	buffered int
	buf      *bytes.Buffer

	// are we done..
	endOfStream bool
}

func (s *STREAM) IsComplete() bool {
	return s.endOfStream
}
