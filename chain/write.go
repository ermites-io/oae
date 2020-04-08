package chain

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
)

var (
	ErrChainInit = errors.New("init error")
)

// TODO implement CHAIN writer
//
//
//
//
//
// THE NEW CHAIN WRITER
//
//
//
//
//
func NewWriter(w io.Writer, a cipher.AEAD, seed, ad []byte, blockSize int) (*CHAIN, error) {
	buffer := make([]byte, 0, blockSize)

	seedlen := a.NonceSize()
	if len(seed) < seedlen {
		return nil, ErrChainInit
	}

	// setup the seed for STREAM nonce generation
	state := newState(seed[:seedlen])

	c := CHAIN{
		aead:  a,
		ad:    ad,
		state: state,
		w:     w,
		buf:   bytes.NewBuffer(buffer),
	}

	return &c, nil
}
