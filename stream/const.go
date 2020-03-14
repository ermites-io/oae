package stream

const (
	NonceOverHead    = 4 + 1 // [ 4 bytes counter ] [ 1 byte tag ]
	DefaultBlockSize = 64 * 1024
	EOS              = 0x01
)
