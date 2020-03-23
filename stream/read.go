package stream

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
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
func NewReader(r io.Reader, a cipher.AEAD, seed, ad []byte, blockSize int) (*STREAM, error) {
	buffer := make([]byte, 0, blockSize)

	seedlen := a.NonceSize() - NonceOverhead
	if len(seed) < seedlen {
		return nil, ErrStreamInit
	}

	// seed size depends on aead nonce size.
	s := STREAM{
		aead:        a,
		ad:          ad,
		state:       newState(seed[:seedlen]),
		r:           r,
		buf:         bytes.NewBuffer(buffer),
		endOfStream: false,
	}
	return &s, nil
}

// if n < len(p) -> error
// if n < len(p) internally -> blocking call
// if n == len(p) & EOF -> error io.EOF || nil

func (s *STREAM) SeekBlock(block int) {
	s.state.set(block)
}

func (s *STREAM) Block() uint32 {
	return s.state.block
}

func (s *STREAM) Read(p []byte) (n int, err error) {
	blocksize := s.buf.Cap()

	if len(p) == 0 {
		return 0, nil
	}

	//buf := make([]byte, s.buf.len()+s.aead.Overhead())
	buf := make([]byte, blocksize+s.aead.Overhead())

	// so we read one block from the reader, e aead.Open()
	// my internal buffer is smaller,
	// than the len of the dest buffer, i need to fill it  before i return..
	// exit case are:
	// n == 0 && err == io.EOF
	// n > 0 && io.ErrUnexpectedEOF
	// err != nil
	//bufsize := s.buf.Cap() // 16 bytes
	//fmt.Fprintf(os.Stderr, "Read() len(b): %d bufsize: %d\n", len(p), blocksize)

	if s.buf.Len() > 0 {
		//fmt.Fprintf(os.Stderr, "BUFFER FILLED\n")
		tmpbuf := s.buf.Bytes()
		n0 := copy(p, tmpbuf)
		//fmt.Fprintf(os.Stderr, "BUFFER FILLED COPIED: %d / %d\n", n0, len(tmpbuf))
		s.buf.Reset()
		_, err = s.buf.Write(tmpbuf[n0:])
		if err != nil {
			//panic(err)
			return
		}
		n += n0
	}

	// if the dest buffer is larger than our internal buffer,
	// let's just loop and fill as much.
forloop:
	for b := p[n:]; n < len(p); {

		n1, rerr := io.ReadFull(s.r, buf)
		//fmt.Fprintf(os.Stderr, "-- readfull() n: %d n1: %d rerr: %v\n", n, n1, rerr)
		switch rerr {
		case io.EOF:
			err = io.EOF
			break forloop
		case io.ErrUnexpectedEOF:
			// it is the last block (we use ReadFull())
			nonce := s.state.next(true)
			pt, cerr := s.aead.Open(nil, nonce, buf[:n1], s.ad)
			if cerr != nil {
				// TRUNCATED BLOCK so we are not returning EOF or nil
				// it's TRUNCATED it's supposed to be the last block or we miss data.
				err = fmt.Errorf("block: %d %v", s.state.block-1, cerr)
				//err = cerr
				break forloop
			}
			n0 := copy(b, pt)
			if n0 < len(pt) {
				// buffer the remaining that has already been decrypted..
				_, werr := s.buf.Write(pt[n0:])
				//fmt.Fprintf(os.Stderr, "BUFFER CN: %d\n", cn)
				if werr != nil {
					// we should not PANIC, but let's return that error.
					//panic(err) // TODO better handling..
					err = werr
					break forloop
				}
			}
			//fmt.Fprintf(os.Stderr, "unexEOF len(pt):%d VS n0: %d\n", len(pt), n0)
			b = b[n0:]
			n += n0
			s.endOfStream = true
			break forloop
		case nil:
			nonce := s.state.next(false)
			pt, cerr := s.aead.Open(nil, nonce, buf[:n1], s.ad)
			if cerr != nil {
				// may be it's the last block.
				//nonce[len(nonce)-1] = 0x01
				nonce.last()
				pt, cerr = s.aead.Open(nil, nonce, buf[:n1], s.ad)
				if cerr != nil {
					// the guess is it's the last block
					// since we're in % blocksize
					// if not and we should just return an ErrUnexpectedEOF
					//panic(err)
					err = fmt.Errorf("block: %d %v", s.state.block-1, cerr)
					break forloop
				}
				s.endOfStream = true
			}

			n0 := copy(b, pt)
			if n0 < len(pt) {
				// buffer the remaining that has already been decrypted..
				_, werr := s.buf.Write(pt[n0:])
				if werr != nil {
					err = fmt.Errorf("block: %d %v", s.state.block-1, werr)
					//err = werr
					break forloop
				}
			}
			//fmt.Fprintf(os.Stderr, "NIL len(pt):%d VS n0: %d\n", len(pt), n0)
			b = b[n0:]
			n += n0
		default:
			// better handling?
			panic(rerr)
		}
	}
	return
}
