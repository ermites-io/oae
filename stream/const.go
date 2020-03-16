package stream

// NEED CONST ERRORS
type Error string

func (e Error) Error() string { return string(e) }

const (
	NonceOverhead    = 4 + 1 // [ 4 bytes counter ] [ 1 byte tag ]
	DefaultBlockSize = 64 * 1024
	EOS              = 0x01

	ErrStreamInit = Error("STREAM initialization error")
)
