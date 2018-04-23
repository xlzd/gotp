package gotp

import (
	"crypto/hmac"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"strings"
)

type OTP struct {
	secret string   // secret in base32 format
	digits int      // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	digest hashFunc // digest function to use in the HMAC (expected to be sha1)
}

type hashFunc = func() hash.Hash

func NewOTP(secret string, digits int, digest hashFunc) OTP {
	return OTP{
		secret: secret,
		digits: digits,
		digest: digest,
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
	hasher := hmac.New(o.digest, o.byteSecret())
	hasher.Write(Itob(input))
	hmacHash := hasher.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(o.digits))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code)
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
