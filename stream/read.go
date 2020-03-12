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

// if n < len(p) -> error
// if n < len(p) internally -> blocking call
// if n == len(p) & EOF -> error io.EOF || nil

func (s *STREAM) Seek(offset int64, whence int) (off int64, err error) {
	blocksize := s.buf.Cap()

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

	// need to calculate how many blocks we need to read..
	// [ seed ] [ block 0 ] [ block 1 ] [ block 2 ]... [ block n ]
	// 0
	switch whence {
	case io.SeekStart:
		// progress the state up to the offset
		//which block should I reading
		bn := offset / int64(blocksize)
		bm := offset % int64(blocksize)

		fmt.Fprintf(os.Stderr, "BNum: %v BMod: %v\n", bn, bm)
		if bn > 0 {
			buf := make([]byte, blocksize)
			// read each block until we reach our limit
			for i := 0; i < int(bn); i++ {
				n0, rerr := s.Read(buf)
				if rerr != nil {
					panic(err)
				}
				fmt.Fprintf(os.Stderr, "ReadAt Loop(%d) n0: %d err: %v\n", i, n0, err)
			}
		}

		/* granularity is block size
		if bm > 0 {
			buf := make([]byte, bm)
			n0, rerr := s.Read(buf)
			if rerr != nil {
				panic(err)
			}
			fmt.Fprintf(os.Stderr, "ReadAt Modulo(%d) n0: %d err: %v\n", bm, n0, err)
		}
		*/
	case io.SeekCurrent: // NOT SUPPORTED
	case io.SeekEnd: // NOT SUPPORTED
	}

	//s.state.set(bn)

	return
}

func (s *STREAM) Read(p []byte) (n int, err error) {
	blocksize := s.buf.Cap()

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
		_, err := s.buf.Write(tmpbuf[n0:])
		if err != nil {
			panic(err)
		}
		n += n0
	}

	// if the dest buffer is larger than our internal buffer,
	// let's just loop and fill as much.
goout:
	//for b := p; n < len(p); {
	for b := p[n:]; n < len(p); {
		var nonce []byte

		n1, rerr := io.ReadFull(s.r, buf)
		//fmt.Fprintf(os.Stderr, "-- readfull() n: %d n1: %d rerr: %v\n", n, n1, rerr)
		switch rerr {
		case io.EOF:
			err = io.EOF
			break goout
		case io.ErrUnexpectedEOF:
			// it is the last block (we use ReadFull())
			nonce = s.state.next(true)
			pt, err := s.aead.Open(nil, nonce, buf[:n1], nil)
			if err != nil {
				// TRUNCATED BLOCK so we are not returning EOF or nil
				// it's TRUNCATED it's supposed to be the last block or we miss data.
				err = rerr
				break goout
			}
			n0 := copy(b, pt)
			if n0 < len(pt) {
				// buffer the remaining that has already been decrypted..
				_, werr := s.buf.Write(pt[n0:])
				//fmt.Fprintf(os.Stderr, "BUFFER CN: %d\n", cn)
				if err != nil {
					// we should not PANIC, but let's return that error.
					//panic(err) // TODO better handling..
					err = werr
					break goout
				}
			}
			//fmt.Fprintf(os.Stderr, "unexEOF len(pt):%d VS n0: %d\n", len(pt), n0)
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
					// the guess is it's the last block
					// since we're in % blocksize
					// if not and we should just return an ErrUnexpectedEOF
					//panic(err)
					err = io.ErrUnexpectedEOF
					break goout
				}
			}

			n0 := copy(b, pt)
			if n0 < len(pt) {
				// buffer the remaining that has already been decrypted..
				_, werr := s.buf.Write(pt[n0:])
				//fmt.Fprintf(os.Stderr, "BUFFER CN: %d\n", cn)
				if werr != nil {
					//panic(err) // TODO better handling..
					err = werr
					break goout
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
