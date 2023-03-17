package signedstrings_test

import (
	"encoding/hex"
	"flag"
	"fmt"
	"testing"

	"github.com/andreyvit/signedstrings"
)

var exampleKey = must(hex.DecodeString("d850af431064164d9a73891fa0a257ba91e5cb18a67de07d3507b8ccdc8781c2"))

func Example_token() {
	conf := signedstrings.Configuration{
		Keys:     [][]byte{exampleKey},
		Prefixes: []string{"TOKEN-"},
	}

	fmt.Println(conf.Sign("foo"))

	print(conf.Validate("TOKEN-foo-4bc019e2218479926f27694a281b8b2af30f86f5f522d0bbde31ab19bc730f39"))

	print(conf.Validate(""))
	print(conf.Validate("foo-4bc019e2218479926f27694a281b8b2af30f86f5f522d0bbde31ab19bc730f39"))
	print(conf.Validate("TOKEN-foo-1111111111111111111111111111111111111111111111111111111111111111"))
	// Output: TOKEN-foo-4bc019e2218479926f27694a281b8b2af30f86f5f522d0bbde31ab19bc730f39
	// foo
	// err: invalid string
	// err: invalid string
	// err: invalid signature
}

func Example_plain() {
	conf := signedstrings.Configuration{
		Keys: [][]byte{exampleKey},
		Sep:  " :: ",
	}

	fmt.Println(conf.Sign("some text to sign"))

	print(conf.Validate("some text to sign :: 2f9a0cb84617f6e394a22068504f59ba3e7903c4dc1fd995cc4a940ffeef90d8"))

	print(conf.Validate(" :: "))
	print(conf.Validate("some text to sign"))
	print(conf.Validate("some text to sign :: 1111111111111111111111111111111111111111111111111111111111111111"))

	// Output: some text to sign :: 2f9a0cb84617f6e394a22068504f59ba3e7903c4dc1fd995cc4a940ffeef90d8
	// some text to sign
	// err: invalid string
	// err: invalid string
	// err: invalid signature
}

func ExampleParseKeys() {
	// WARNING: use longer keys, these are very short, for demonstration only
	keys, err := signedstrings.ParseKeys("d850af431064164d9a73891fa0a257ba91e5cb18a67de07d3507b8ccdc8781c2 65ce238cb1b11d17a00c94c875394f500b05abd24c276a01691bdf9ce00d213c,,,283d54389c394ed33ba4146eff7b4133f7e393cb905d089a06798456a1cb7dcd")
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.EncodeToString(keys[0]))
	fmt.Println(hex.EncodeToString(keys[1]))
	fmt.Println(hex.EncodeToString(keys[2]))

	print(signedstrings.ParseKeys("zzz"))
	print(signedstrings.ParseKeys("d850"))

	// Output: d850af431064164d9a73891fa0a257ba91e5cb18a67de07d3507b8ccdc8781c2
	// 65ce238cb1b11d17a00c94c875394f500b05abd24c276a01691bdf9ce00d213c
	// 283d54389c394ed33ba4146eff7b4133f7e393cb905d089a06798456a1cb7dcd
	// err: encoding/hex: invalid byte: U+007A 'z'
	// err: 2-byte key is too short, need at least 32 bytes
}

func ExampleKeys() {
	var keys signedstrings.Keys
	flags := flag.NewFlagSet("", flag.PanicOnError)
	flags.Var(&keys, "keys", "explanation")
	flags.Parse([]string{"-keys", "d850af431064164d9a73891fa0a257ba91e5cb18a67de07d3507b8ccdc8781c2,65ce238cb1b11d17a00c94c875394f500b05abd24c276a01691bdf9ce00d213c"})
	fmt.Println(keys)
	// Output: d850af431064164d9a73891fa0a257ba91e5cb18a67de07d3507b8ccdc8781c2 65ce238cb1b11d17a00c94c875394f500b05abd24c276a01691bdf9ce00d213c
}

func TestSanityCheck_noKeys(t *testing.T) {
	conf := signedstrings.Configuration{}
	assertPanic(t, "signedstrings: not configured", func() {
		conf.Sign("foo")
	})
}

func TestSanityCheck_emptyKey(t *testing.T) {
	conf := signedstrings.Configuration{
		Keys: [][]byte{
			exampleKey,
			{},
		},
	}
	assertPanic(t, "signedstrings: empty key", func() {
		conf.Sign("foo")
	})
}

func TestSanityCheck_shortKey(t *testing.T) {
	conf := signedstrings.Configuration{
		Keys: [][]byte{
			{1, 2, 3, 4},
		},
	}
	assertPanic(t, "signedstrings: short key", func() {
		conf.Sign("foo")
	})
}

func print(v any, err error) {
	if err != nil {
		fmt.Println("err: " + err.Error())
	} else {
		fmt.Println(v)
	}
}

func assertPanic(t testing.TB, msg string, f func()) {
	defer func() {
		v := recover()
		if v == nil {
			t.Errorf("didn't panic, expected to panic with %q", msg)
		} else if s := fmt.Sprint(v); s != msg {
			t.Errorf("paniced with %q, expected to panic with %q", s, msg)
		}
	}()
	f()
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
