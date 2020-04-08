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

STREAM is in, CHAIN is starting.


```
import (
	"github.com/ermites-io/oae/stream"
	"github.com/ermites-io/oae/chain"
)

func main() {
..
	// STREAM construction
	stw, err := stream.NewWriter(w, aead, nonce, ad, 32768) // you get an io.Writer
	str, err := stream.NewReader(r, aead, nonce, ad, 32768) // you get an io.Reader

	// CHAIN construction
```

