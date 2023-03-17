Go HMAC-SHA256 signing
======================

[![Go reference](https://pkg.go.dev/badge/github.com/andreyvit/signedstrings.svg)](https://pkg.go.dev/github.com/andreyvit/signedstrings) ![zero dependencies](https://img.shields.io/badge/deps-zero-brightgreen) ![under 150 LOC](https://img.shields.io/badge/size-%3C200%20LOC-green) ![great coverage](https://img.shields.io/badge/coverage-98%25-green) [![Go report card](https://goreportcard.com/badge/github.com/andreyvit/signedstrings)](https://goreportcard.com/report/github.com/andreyvit/signedstrings)


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
* parsing of the signed message (`strings.CutLast` would be so nice to have);
* sanity checks to avoid signing something with an empty key due to misconfiguration;
* maybe even adding a prefix to identify the tokens (for security leak prevention, log sanitization and input sanity checking purposes);

...all without littering your code with these uninteresting details. That's where `signedstrings` comes in, a tiny utility library.

IMPORTANT: `signedstrings` does NOT add a timestamp or a random nonce, and will always return the same string given the same inputs. This will enable replay attacks in certain use cases. As a professional, you are expected to know what you're doing when using security primitives, HMAC-SHA256 included. If you don't, you REALLY should not be writing security-sensitive code, sorry.


Usage
-----

Install:

    go get github.com/andreyvit/signedstrings

Use:

```go
conf := &signedstrings.Configuration{
    Prefixes: []string{"MYAPPTOKEN-"}, // optional!
}
flag.Var(&conf.Keys, "signing-keys", "key(s) for signed tokens") // or envflag.Var

...
signed := conf.Sign("foo")
// MYAPPTOKEN-foo-1c54...7a1e

...
data, err := conf.Validate(signed)
// data == "foo"
// errors: signedstrings.Invalid, signedstrings.InvalidSig
```

IMPORTANT: `signedstrings` does NOT add a timestamp or a random nonce, and will always return the same string given the same inputs. This will enable replay attacks in certain use cases. As a professional, you are expected to know what you're doing when using security primitives, HMAC-SHA256 included. If you don't, you REALLY should not be writing security-sensitive code, sorry.


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
