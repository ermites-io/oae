[![Documentation](https://godoc.org/github.com/ermites-io/oae?status.svg)](http://godoc.org/github.com/ermites-io/oae)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)


oae
====

a STREAM & CHAIN Contruction Online Authenticated Encryption package


Description
===========

[Online Authenticate Encryption and its nonce reuse misuse resistance](https://eprint.iacr.org/2015/189.pdf)

standard library based package to provide "online" authenticated encryption reader / writer facilities using 
STREAM & CHAIN construction using any cipher.AEAD.


How to use
==========

This is WORK IN PROGRESS...  reliable code should come shortly as we need it.

The API is still being worked, especially with AD.

stream is partly in, chain is not commited in yet.


```
import (
	"github.com/ermites-io/oae/stream"
	"github.com/ermites-io/oae/chain"
)

func main() {
..
	// STREAM construction
	stw, err := stream.NewWriter()
	str, err := stream.NewReader()

	// CHAIN construction
	chw, err := chain.NewWriter()
	chr, err := chain.NewReader()
```

