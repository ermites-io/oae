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
	ad   []byte      // AEAD additionnal data, like stream id for example.

	state *state // the state of the stream

	w io.Writer // writer
	r io.Reader // reader

	buffered int
	buf      *bytes.Buffer

	blocksize int

	// are we done..
	endOfStream bool
}

func (s *STREAM) IsComplete() bool {
	return s.endOfStream
}

func (s *STREAM) BlockSize() int {
	return s.blocksize
}


// try to predict the output size
func (s *STREAM) StreamSize(len int) int {
	numBlocks := len / s.blocksize
	numBlocksRemain := len % s.blocksize

	total := numBlocks * s.aead.Overhead()
	if numBlocksRemain != 0 {
		total += s.aead.Overhead()
	}

	return total;
}

