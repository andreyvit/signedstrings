package signedstrings

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

type Configuration struct {
	// Keys are accepted when validating signatures. The first key is the one used
	// when signing new messages. Multiple valid keys allow for key rotation.
	Keys Keys

	// Prefixes are added in front of the tokens to help identify them.
	// The first one is used for new tokens. Others are accepted when
	// validating tokens to allow prefix changes.
	//
	// An empty prefix is a valid choice. Omitting this field is the same as
	// specifying a single empty prefix.
	Prefixes []string

	// Sep is the separator between the data and the signature, a cosmetic choice.
	// Defaults to a dash.
	Sep string
}

var (
	// Invalid is the error returning for incorrectly formatted signed messages.
	Invalid = errors.New("invalid string")
	// InvalidSig is the error returned for correctly formatted signed messages that
	// do not pass signature validation (ie have been corrupted or tampered with).
	InvalidSig = errors.New("invalid signature")
)

// Sign signs the given string (and adds a configured prefix if any).
func (conf *Configuration) Sign(data string) string {
	conf.sanityCheck()

	msg := data
	if len(conf.Prefixes) > 0 {
		msg = conf.Prefixes[0] + msg
	}

	auth := hmacSHA256([]byte(msg), conf.Keys[0])
	return msg + conf.sep() + auth
}

// Validate verifies the signature on the given string, and returns the original
// value if the signature is valid.
func (conf *Configuration) Validate(signed string) (string, error) {
	conf.sanityCheck()

	msg, auth, ok := cutLast(signed, conf.sep())
	if !ok || len(auth) == 0 {
		return "", Invalid
	}

	data, idx := cutLongestPrefix(msg, conf.prefixes())
	if idx < 0 {
		return "", Invalid
	}

	keyIndex := -1
	for i, key := range conf.Keys {
		expected := hmacSHA256([]byte(msg), key)
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) == 1 {
			keyIndex = i
			break
		}
	}
	if keyIndex < 0 {
		return "", InvalidSig
	}

	return data, nil
}

func (conf *Configuration) sanityCheck() {
	if len(conf.Keys) == 0 {
		panic("signedstrings: not configured")
	}
	for _, key := range conf.Keys {
		if len(key) == 0 {
			panic("signedstrings: empty key")
		}
	}
}

func (conf *Configuration) sep() string {
	if s := conf.Sep; len(s) > 0 {
		return s
	}
	return "-"
}

func (conf *Configuration) prefixes() []string {
	if v := conf.Prefixes; len(v) > 0 {
		return v
	}
	return emptyPrefixes
}

// ParseKeys parses a comma or whitespace-separated list of hex-encoded keys.
func ParseKeys(s string) (Keys, error) {
	var keys [][]byte
	for _, ks := range strings.FieldsFunc(s, isWhitespaceOrComma) {
		key, err := hex.DecodeString(ks)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Keys is a convenience type for a list of []byte keys. Can be used with flag.Var
// and its compatibles. Defines a sensible String().
type Keys [][]byte

func (v Keys) String() string {
	var buf strings.Builder
	for i, k := range v {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(hex.EncodeToString(k))
	}
	return buf.String()
}

func (v Keys) Get() interface{} {
	return [][]byte(v)
}

func (v *Keys) Set(raw string) (err error) {
	*v, err = ParseKeys(raw)
	return
}

func isWhitespaceOrComma(r rune) bool {
	return r == ' ' || r == ','
}

func hmacSHA256(message, key []byte) string {
	var hash [sha256.Size]byte
	alg := hmac.New(sha256.New, key)
	alg.Write(message)
	alg.Sum(hash[:0])
	return hex.EncodeToString(hash[:])
}

var emptyPrefixes = []string{""}

func cutLongestPrefix(str string, prefixes []string) (after string, index int) {
	index = -1
	for i, p := range prefixes {
		if a, found := strings.CutPrefix(str, p); found {
			if index < 0 || len(p) > len(prefixes[index]) {
				after, index = a, i
			}
		}
	}
	return
}

// cutLast slices s around the last instance of sep, returning the text before and after sep.
// The found result reports whether sep appears in s.
// If sep does not appear in s, cut returns s, "", false.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
