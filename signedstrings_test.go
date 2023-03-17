package signedstrings_test

import (
	"encoding/hex"
	"flag"
	"fmt"
	"testing"

	"github.com/andreyvit/signedstrings"
)

func Example_token() {
	conf := signedstrings.Configuration{
		Keys:     [][]byte{[]byte("hello world")},
		Prefixes: []string{"TOKEN-"},
	}

	fmt.Println(conf.Sign("foo"))

	print(conf.Validate("TOKEN-foo-1c54d5a9d70312670528e4046ccdad77d97dcd2bcccdc161f25dd63dd7c97a1e"))

	print(conf.Validate(""))
	print(conf.Validate("foo-1c54d5a9d70312670528e4046ccdad77d97dcd2bcccdc161f25dd63dd7c97a1e"))
	print(conf.Validate("TOKEN-foo-1111111111111111111111111111111111111111111111111111111111111111"))
	// Output: TOKEN-foo-1c54d5a9d70312670528e4046ccdad77d97dcd2bcccdc161f25dd63dd7c97a1e
	// foo
	// err: invalid string
	// err: invalid string
	// err: invalid signature
}

func Example_plain() {
	conf := signedstrings.Configuration{
		Keys: [][]byte{[]byte("hello world")},
		Sep:  " :: ",
	}

	fmt.Println(conf.Sign("some text to sign"))

	print(conf.Validate("some text to sign :: 3fa50b5e152cc7eeb37bd0f9e9e4bb61ee3c31939e97f020fb154f3a01cfd441"))

	print(conf.Validate(" :: "))
	print(conf.Validate("some text to sign"))
	print(conf.Validate("some text to sign :: 1111111111111111111111111111111111111111111111111111111111111111"))

	// Output: some text to sign :: 3fa50b5e152cc7eeb37bd0f9e9e4bb61ee3c31939e97f020fb154f3a01cfd441
	// some text to sign
	// err: invalid string
	// err: invalid string
	// err: invalid signature
}

func ExampleParseKeys() {
	// WARNING: use longer keys, these are very short, for demonstration only
	keys, err := signedstrings.ParseKeys("787653b737a07fa0 d5d73e9d64076e18,,,81b5a01659b74a84")
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.EncodeToString(keys[0]))
	fmt.Println(hex.EncodeToString(keys[1]))
	fmt.Println(hex.EncodeToString(keys[2]))

	print(signedstrings.ParseKeys("zzz"))

	// Output: 787653b737a07fa0
	// d5d73e9d64076e18
	// 81b5a01659b74a84
	// err: encoding/hex: invalid byte: U+007A 'z'
}

func ExampleKeys() {
	var keys signedstrings.Keys
	flags := flag.NewFlagSet("", flag.PanicOnError)
	flags.Var(&keys, "keys", "explanation")
	flags.Parse([]string{"-keys", "787653b737a07fa0,d5d73e9d64076e18"})
	fmt.Println(keys)
	// Output: 787653b737a07fa0 d5d73e9d64076e18
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
			{1, 2, 3, 4},
			{},
			{5, 6, 7, 8},
		},
	}
	assertPanic(t, "signedstrings: empty key", func() {
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
