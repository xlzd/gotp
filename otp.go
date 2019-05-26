package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"strings"
)

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

type OTP struct {
	secret     string  // secret in base32 format
	digits     int     // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	hasher     *Hasher // digest function to use in the HMAC (expected to be sha1)
	formatting string  // Saves the format an OTP is generated with
}

// Format sets the output format of the OTP
type Format int

// Invalid format will cause a panic
const (
	Unknown Format = iota
	FormatDec
	FormatHex
)

func NewOTP(secret string, digits int, hasher *Hasher, format Format) OTP {
	if hasher == nil {
		hasher = &Hasher{
			HashName: "sha1",
			Digest:   sha1.New,
		}
	}

	var formatting string
	switch format {
	case FormatDec:
		formatting = fmt.Sprintf("%%0%dd", digits)
	case FormatHex:
		formatting = fmt.Sprintf("%%0%dx", digits)
	default:
		panic(fmt.Errorf("unknown output format selected: %v", format))
	}

	return OTP{
		secret:     secret,
		digits:     digits,
		hasher:     hasher,
		formatting: formatting,
	}
}

/*
params
    input: the HMAC counter value to use as the OTP input. Usually either the counter, or the computed integer based on the Unix timestamp
*/
func (o *OTP) generateOTP(input int) string {
	if input < 0 {
		panic("input must be positive integer")
	}
	hasher := hmac.New(o.hasher.Digest, o.byteSecret())
	hasher.Write(Itob(input))
	hmacHash := hasher.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(o.digits))
	return fmt.Sprintf(o.formatting, code)
}

func (o *OTP) byteSecret() []byte {
	missingPadding := len(o.secret) % 8
	if missingPadding != 0 {
		o.secret = o.secret + strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(o.secret)
	if err != nil {
		panic("decode secret failed")
	}
	return bytes
}
