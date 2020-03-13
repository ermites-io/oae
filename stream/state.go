package stream

import (
	"encoding/binary"
)

// stream state will be quite different
// it will start like this:
// newState(salt, seed, noncesize)
// state will be:
//   - next()
//   - last()
// but it is not clear whether each nonce will just increment its counter..
// i guess yes.. from the paper.. it seems like it
// Example:
// AES-GCM  Nonce is 96 bits (12 bytes)
// [ 7 bytes rand ] [ 4 bytes counter ] [ 1 byte d ]
// Xchacha20 Nonce is 192 bits (24 bytes)
// [ 19 bytes rand ] [ 4 bytes counter ] [ 1 byte d ]

//
//
//
//
//
// THE NEW STREAM STATE
//
//
//
//
//

// the new stream state
type state struct {
	init  bool
	block uint32 // the number of blocks 2^32 block or 32/64K == 140 PB / 281 PB enough i guess..
	seed  []byte
}

func newState(seed []byte) *state {
	return &state{
		init:  false,
		block: 0,
		seed:  seed,
	}
}

func (s *state) set(block int) {
	s.block = uint32(block)
}

// better naming later.
//func (s *state) init() bool {
func (s *state) start() {
	/*
		if s.block == 0 {
			return true
		}
		return false
	*/
	s.init = true
}

func (s *state) started() bool {
	return s.init
}

func (s *state) Init() bool {
	if s.block == 0 {
		return true
	}
	return false
}

// compute the  next nonce
// [ seed ] [ block ] [ tag ]
// seed : depend on AEAD nonce size
// block : 4 bytes
// tag : 1 byte
// if last is true then the tag is 0x01 and mark the end of the stream
func (s *state) next(last bool) (nonce []byte) {
	//var nonce []byte

	// tag
	t := make([]byte, 1)

	// prepare block number
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, s.block)

	// prepare tag
	if last {
		t[0] = 0x01
	}

	nonce = append(nonce, s.seed...)
	nonce = append(nonce, b...)
	nonce = append(nonce, t...)

	// increment
	s.block++

	// now we have the nonce..
	// not sure if we need to apply transformations..
	return
}
