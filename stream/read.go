package stream

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
)

//
//
//
//
//
// THE NEW STREAM READER
//
//
//
//
//
func NewReader(r io.Reader, a cipher.AEAD, blockSize int) (*STREAM, error) {
	buffer := make([]byte, 0, blockSize)

	s := STREAM{
		aead: a,
		r:    r,
		buf:  bytes.NewBuffer(buffer),
	}
	return &s, nil
}

func (s *STREAM) Read(p []byte) (n int, err error) {
	bufsize := s.buf.Cap()

	if len(p) == 0 {
		return 0, nil
	}

	// are we in the beginning?
	// yes read the seed first and create the state from it.
	if s.state == nil {
		seed := make([]byte, s.aead.NonceSize()-4-1)

		// read block0
		_, err = io.ReadFull(s.r, seed)
		//fmt.Printf("read header %d bytes\n", n)
		if err != nil {
			//fmt.Printf("read header %d (%v)\n", n, err)
			return
		}
		s.state = newState(seed)
	}

	//buf := make([]byte, s.buf.len()+s.aead.Overhead())
	buf := make([]byte, bufsize+s.aead.Overhead())

	// so we read one block from the reader, e aead.Open()
	// my internal buffer is smaller,
	// than the len of the dest buffer, i need to fill it  before i return..
	// exit case are:
	// n == 0 && err == io.EOF
	// n > 0 && io.ErrUnexpectedEOF
	// err != nil
	//bufsize := s.buf.Cap() // 16 bytes
	fmt.Fprintf(os.Stderr, "Read() len(b): %d bufsize: %d\n", len(p), bufsize)

	if s.buf.Len() > 0 {
		fmt.Fprintf(os.Stderr, "BUFFER FILLED\n")
		tmpbuf := s.buf.Bytes()
		n0 := copy(p, tmpbuf)
		fmt.Fprintf(os.Stderr, "BUFFER FILLED COPIED: %d / %d\n", n0, len(tmpbuf))
		s.buf.Reset()
		_, err := s.buf.Write(tmpbuf[n0:])
		if err != nil {
			panic(err)
		}
		n += n0
	}

	// if the dest buffer is larger than our internal buffer,
	// let's just loop and fill as much.
goout:
	for b := p; n < len(p); {
		var nonce []byte

		n1, rerr := io.ReadFull(s.r, buf)
		fmt.Fprintf(os.Stderr, "we readfull() n1: %d rerr: %v\n", n1, rerr)
		switch rerr {
		case io.EOF:
			err = io.EOF
			break goout
		case io.ErrUnexpectedEOF:
			// OLD
			nonce = s.state.next(true)
			pt, err := s.aead.Open(nil, nonce, buf[:n1], nil)
			if err != nil {
				// TRUNCATED BLOCK so we are not returning EOF or nil
				// it's TRUNCATED it's supposed to be the last block or we miss data.
				err = rerr
				break goout
			}
			n0 := copy(b, pt)
			fmt.Fprintf(os.Stderr, "len(pt):%d VS n0: %d\n", len(pt), n0)
			b = b[n0:]
			n += n0
			break goout
		case nil:
			nonce = s.state.next(false)
			pt, err := s.aead.Open(nil, nonce, buf[:n1], nil)
			if err != nil {
				// may be it's the last block.
				nonce[len(nonce)-1] = 0x01
				pt, err = s.aead.Open(nil, nonce, buf[:n1], nil)
				if err != nil {
					panic(err)
				}
			}

			n0 := copy(b, pt)
			if n0 < len(pt) {
				// buffer the remaining that has already been decrypted..
				cn, err := s.buf.Write(pt[n0:])
				fmt.Fprintf(os.Stderr, "BUFFER CN: %d\n", cn)
				if err != nil {
					panic(err) // TODO better handling..
				}
			}
			fmt.Fprintf(os.Stderr, "len(pt):%d VS n0: %d\n", len(pt), n0)
			b = b[n0:]
			n += n0
		default:
			panic(rerr)
		}
	}
	//fmt.Fprintf(os.Stderr, "RET Read() n: %d err: %v\n", n, err)
	return
}
