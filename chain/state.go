package chain

type nonce []byte

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
