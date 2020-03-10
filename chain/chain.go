package chain

import "io"

type CHAIN struct {
	s *chainState

	// next writer layer
	w io.Writer
	// next reader layer
	r io.Reader
}
