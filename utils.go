package gotp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	OtpTypeTotp = "totp"
	OtpTypeHotp = "hotp"
)

/*
Returns the provisioning URI for the OTP; works for either TOTP or HOTP.
This can then be encoded in a QR Code and used to provision the Google Authenticator app.
For module-internal use.
See also:
    https://github.com/google/google-authenticator/wiki/Key-Uri-Format

params:
    otpType：     otp type, must in totp/hotp
    secret:       the hotp/totp secret used to generate the URI
    accountName:  name of the account
    issuerName:   the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator
    algorithm:    the algorithm used in the OTP generation
    initialCount: starting counter value. Only works for hotp
    digits:       the length of the OTP generated code.
    period:       the number of seconds the OTP generator is set to expire every code.

returns: provisioning uri
*/
func BuildUri(otpType, secret, accountName, issuerName, algorithm string, initialCount, digits, period int) string {
	q := url.Values{}

	if otpType != OtpTypeHotp && otpType != OtpTypeTotp {
		panic("otp type error, got " + otpType)
	}
	label := url.QueryEscape(accountName)
	if issuerName != "" {
		label = url.QueryEscape(issuerName) + ":" + label
		q.Set("issuer", issuerName)
	}
	q.Set("secret", secret)
	if algorithm != "" && algorithm != "sha1" {
		q.Set("algorithm", strings.ToUpper(algorithm))
	}
	if digits != 0 && digits != 6 {
		q.Set("digits", fmt.Sprintf("%d", digits))
	}
	if period != 0 && period != 30 {
		q.Set("period", fmt.Sprintf("%d", period))
	}
	if otpType == OtpTypeHotp {
		q.Set("counter", fmt.Sprintf("%d", initialCount))
	}
	u := url.URL{
		Scheme:   "otpauth",
		Host:     otpType,
		Path:     label,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// get current timestamp
func currentTimestamp() int {
	return int(time.Now().UTC().Unix())
}

// integer to byte array
func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

// generate a random secret of given length (number of bytes)
// returns empty string if something bad happened
func RandomSecret(length int) string {
	var result string
	secret := make([]byte, length)
	gen, err := rand.Read(secret)
	if err != nil || gen != length {
		// error reading random, return empty string
		return result
	}
	var encoder = base32.StdEncoding.WithPadding(base32.NoPadding)
	result = encoder.EncodeToString(secret)
	return result
}
