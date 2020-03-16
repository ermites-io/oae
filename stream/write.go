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
// THE NEW STREAM WRITER
//
//
//
//
//
/*
func OldNewWriter(w io.Writer, a cipher.AEAD, blockSize int) (*STREAM, error) {
	buffer := make([]byte, 0, blockSize)
	seed := make([]byte, a.NonceSize()-4-1)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	//fmt.Fprintf(os.Stderr, "seed: %x\n", seed)

	state := newState(seed)

	s := STREAM{
		aead:  a,
		state: state,
		w:     w,
		buf:   bytes.NewBuffer(buffer),
	}

	return &s, nil
}
*/

func NewWriter(w io.Writer, a cipher.AEAD, seed []byte, blockSize int) (*STREAM, error) {
	buffer := make([]byte, 0, blockSize)
	/*
		seed := make([]byte, a.NonceSize()-4-1)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, err
		}
		//fmt.Fprintf(os.Stderr, "seed: %x\n", seed)
	*/
	seedlen := a.NonceSize() - NonceOverhead
	if len(seed) < seedlen {
		return nil, ErrStreamInit
	}

	// setup the seed for STREAM nonce generation
	state := newState(seed[:seedlen])

	s := STREAM{
		aead:  a,
		state: state,
		w:     w,
		buf:   bytes.NewBuffer(buffer),
	}

	return &s, nil
}

/*
func (s *STREAM) writeSeedBlock() (err error) {
	_, err = s.w.Write(s.state.seed)
	return
}
*/

// used by io.Copy()
/*
func (s *STREAM) _ReadFrom(r io.Reader) (wn int64, err error) {
	buf := make([]byte, 0, s.buf.Cap())
	for {
		nr, rerr := io.ReadFull(r, buf)
		//fmt.Fprintf(os.Stderr, "READFROM: n:%d err: %v\n", nr, rerr)
		if nr > 0 {
			nw, werr := s.Write(buf[:nr])
			if nw > 0 {
				wn += int64(nw)
			}

			if werr != nil {
				err = werr
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if rerr != nil {
			if rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
				err = rerr
			}
			break
		}
	} // end of for

	return
}
*/

func (s *STREAM) Write(b []byte) (n int, err error) {
	bufsize := s.buf.Cap()
	unread := len(b)
	//fmt.Fprintf(os.Stderr, "Write(%d) bufsize: %d\n", len(b), bufsize)

	// this is where the seed is transmitted
	// in the beginning of the block
	/*
		if !s.state.started() {
			//if s.state.Init() {
			//fmt.Fprintf(os.Stderr, "started!\n")
			werr := s.writeSeedBlock()
			if werr != nil {
				err = werr
				return
			}
			s.state.start()
		}
	*/

	for wn, avail := 0, bufsize-s.buffered; unread > 0; avail = bufsize - s.buffered {
		// when % bufsize, we do NOT flush, Close() should flush
		// otherwise we cannot tag the last block as last block..
		if s.buffered == bufsize {
			// flush: Seal & Write.
			nonce := s.state.next(false)
			ct := s.aead.Seal(nil, nonce, s.buf.Bytes(), nil)
			_, werr := s.w.Write(ct)
			if werr != nil {
				err = werr
				return
			}
			s.buf.Reset()
			s.buffered = 0
		}

		if unread < avail {
			avail = unread
		}

		towrite := b[n : n+avail]
		wn, err = s.buf.Write(towrite)
		unread -= wn
		n += wn
		s.buffered += wn
	}

	return
}

func (s *STREAM) Close() error {
	last := true

	// Seal and close
	if s.buf.Len() > 0 {
		nonce := s.state.next(last)
		ct := s.aead.Seal(nil, nonce, s.buf.Bytes(), nil)
		_, err := s.w.Write(ct)
		if err != nil {
			return err
		}
		s.buf.Reset()
		s.buffered = 0
	}

	return nil
}
