package stream

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	xcha "golang.org/x/crypto/chacha20poly1305"
)

// ok the test, the infamous tests
// here are the scenarios
//
// write( < 1 block )
// - io.Copy()
// - read( buf = 0)
// - read( buf = 1 bytes ) (repeat until EOF)
// - read( buf = 1 block )
// - read( buf > 1 block )

// redo same tests with:
// - write ( 1 byte )
// - write ( == 1 block )
// - write ( 1 block < n < 2 blocks )
// - write ( 2 blocks )
// - write ( > 2 blocks )

var (
	key = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	}

	blockSize = 16

	readTestVector = []struct {
		blockSize int
		writeSize int
		readSize  int
		readRc    int
		readErr   error
	}{
		{
			16,  // blocksize
			1,   // writesize
			0,   // readsize
			0,   // read expected return
			nil, // read expected error
		},
		{
			16,  // blocksize
			1,   // writesize
			1,   // readsize
			1,   // read expected return
			nil, // read expected error
		},
		{
			16,  // blocksize
			16,  // writesize
			16,  // readsize
			16,  // read expected return
			nil, // read expected error
		},
		{
			16,  // blocksize
			100, // writesize
			100, // readsize
			100, // read expected return
			nil, // read expected error
		},
		{
			16,  // blocksize
			100, // writesize
			64,  // readsize
			64,  // read expected return
			nil, // read expected error
		},
		{
			16,  // blocksize
			2,   // writesize
			64,  // readsize
			2,   // read expected return
			nil, // read expected error
		},
		{
			16,  // blocksize
			2,   // writesize
			20,  // readsize
			2,   // read expected return
			nil, // read expected error
		},
	}
)

// return the hash of the data, the buffer with the encrypted data
func streambuffer(datasize, blocksize int) (dh []byte, iobuffer *bytes.Buffer, err error) {
	data := make([]byte, datasize)

	_, err = io.ReadFull(rand.Reader, data)
	if err != nil {
		return
	}

	// compute hash of the data
	datahash := sha256.Sum256(data)
	dh = datahash[:]

	internal := make([]byte, 0, 64*1024)
	iobuffer = bytes.NewBuffer(internal)

	// prepare the aead...
	aead, err := xcha.NewX(key)
	if err != nil {
		return
	}

	swr, err := NewWriter(iobuffer, aead, blocksize)
	if err != nil {
		return
	}

	_, err = swr.Write(data)
	if err != nil {
		return
	}
	swr.Close()

	return

}

func TestSingleRead(t *testing.T) {
	// prepare the aead...
	aead, err := xcha.NewX(key)
	if err != nil {
		panic(err)
	}

	for i, v := range readTestVector {
		h, iobuf, err := streambuffer(v.writeSize, v.blockSize)
		if err != nil {
			t.Fatalf("[%d] buffer create error: %v\n", i, err)
		}

		srd, err := NewReader(iobuf, aead, v.blockSize)
		if err != nil {
			t.Fatalf("[%d] reader create error: %v\n", i, err)
		}

		b1 := make([]byte, v.readSize)
		rc, err := srd.Read(b1)
		if v.readRc != rc {
			t.Fatalf("[%d] read size error n: %d vs expected: %d\n", i, rc, v.readRc)
		}
		if v.readErr != err {
			t.Fatalf("[%d] read size error: %v vs expected: %v\n", i, err, v.readErr)
		}

		readhash := sha256.Sum256(b1)
		if v.readSize == v.writeSize && bytes.Compare(h, readhash[:]) != 0 {
			t.Fatalf("[%d] read data wh: %x VS rh: %x\n", i, h, readhash[:])
		}
	}
}

func TestMultipleReadUntilEmpty(t *testing.T) {
}
