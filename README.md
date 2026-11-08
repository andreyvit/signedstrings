Go HMAC-SHA256 signing
======================

[![Go reference](https://pkg.go.dev/badge/github.com/andreyvit/signedstrings.svg)](https://pkg.go.dev/github.com/andreyvit/signedstrings) ![zero dependencies](https://img.shields.io/badge/deps-zero-brightgreen) [![Go report card](https://goreportcard.com/badge/github.com/andreyvit/signedstrings)](https://goreportcard.com/report/github.com/andreyvit/signedstrings)


Why?
----

Doing a HMAC-SHA256 is trivial:

```go
func hmacSHA256(message, key []byte) string {
    var hash [sha256.Size]byte
    alg := hmac.New(sha256.New, key)
    alg.Write(message)
    alg.Sum(hash[:0])
    return hex.EncodeToString(hash[:])
}
```

Sometimes, though, you also want:

* key rotation support;
* parsing of the keys;
* parsing of the signed messages (`strings.CutLast` would be so nice to have);
* sanity checks to avoid signing something with an empty or short key due to misconfiguration;
* maybe even adding a prefix to identify the tokens (for security leak prevention, log sanitization and input sanity checking purposes);

...all without littering your code with these uninteresting details. That's where `signedstrings` comes in, a tiny utility library.




Usage
-----

Signing provides integrity, not confidentiality: the original value remains readable. Tokens have no built-in expiry or replay protection. Include and validate an expiry, and track a nonce for one-time actions.

Install:

    go get github.com/andreyvit/signedstrings

Use:

```go
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/andreyvit/signedstrings"
)

func main() {
	// Demo key: store a persistent random key securely for real tokens.
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	conf := &signedstrings.Configuration{
		Keys: signedstrings.Keys{key}, Prefixes: []string{"MYAPPTOKEN-"},
	}
	signed := conf.Sign("foo")
	data, err := conf.Validate(signed)
	if err != nil {
		panic(err)
	}
	fmt.Println(data) // foo
}
```




Generating Keys & Choosing Key Length
-------------------------------------

I recommend 64-byte fully random keys. Generate via `openssl rand -hex 64`. Keys longer than SHA-256’s 64-byte block size are hashed to 32 bytes by HMAC.

[StackOverflow says 32 bytes are enough](https://crypto.stackexchange.com/a/34866), though, if you prefer shorter keys.

IMPORTANT: Note the _fully random_ part. The key should come from a cryptographically secure random number generator like `crypto/rand` or `openssl rand`. Depending on your use case, you might get away with using a non-random key, but in that case, please make sure you know what you are doing. Ditto for other key lengths.

As a secure default, this library will panic when encountering keys shorter than 32 bytes. If you truly want to use shorter keys, adjust the minimum key length:

```go
signedstrings.MinKeyLen = 4  // live dangerously
```


Key & Prefix Rotation
---------------------

You can specify multiple keys and multiple prefixes in your configuration, they will all be accepted for validation. The first key and the first prefix are used to sign new messages. This means you can add a new key or a new prefix while continuing to support prior ones.

Again, note that it's the _first_ key and the _first_ prefix that is used for new signatures. You are supposed to insert keys to the front of the list.


Contributing
------------

This library is feature-complete, but you can always contribute:

* bug fixes
* better documentation and examples
* more tests
* better ways to handle things internally

We recommend [modd](https://github.com/cortesi/modd) (`go install github.com/cortesi/modd/cmd/modd@latest`) for continuous testing during development.


MIT license
-----------

Copyright (c) 2023 Andrey Tarantsov. Published under the terms of the [MIT license](LICENSE).
