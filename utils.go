package gotp

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

const (
	OtpTypeTotp = "totp"
	OtpTypeHotp = "hotp"
)

var (
	// slices of possible runes for secret creation.
	digitRunes   = []rune("0123456789")
	lCaseRunes   = []rune("abcdefghijklmnopqrstuvwxyz")
	uCaseRunes   = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	specialRunes = []rune("~=+%^*/()[]{}/!@#$?|")

	// A collection of all runes which may be used in creating a new secret.
	allRunes = [][]rune{
		digitRunes,
		lCaseRunes,
		uCaseRunes,
		specialRunes,
	}
)

/*
BuildUri returns the provisioning URI for the OTP; works for either TOTP or HOTP.
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
	if otpType != OtpTypeHotp && otpType != OtpTypeTotp {
		panic("otp type error, got " + otpType)
	}

	urlParams := make([]string, 0)
	urlParams = append(urlParams, "secret="+secret)
	if otpType == OtpTypeHotp {
		urlParams = append(urlParams, fmt.Sprintf("counter=%d", initialCount))
	}
	label := url.QueryEscape(accountName)
	if issuerName != "" {
		issuerNameEscape := url.QueryEscape(issuerName)
		label = issuerNameEscape + ":" + label
		urlParams = append(urlParams, "issuer="+issuerNameEscape)
	}
	if algorithm != "" && algorithm != "sha1" {
		urlParams = append(urlParams, "algorithm="+strings.ToUpper(algorithm))
	}
	if digits != 0 && digits != 6 {
		urlParams = append(urlParams, fmt.Sprintf("digits=%d", digits))
	}
	if period != 0 && period != 30 {
		urlParams = append(urlParams, fmt.Sprintf("period=%d", period))
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, label, strings.Join(urlParams, "&"))
}

// currentTimestamp returns the current timestamp.
func currentTimestamp() int {
	return int(time.Now().Unix())
}

// Itob converts an integer to byte array
func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

// RandomSecret generates a random secret of given length from all possible printable ASCII characters.
func RandomSecret(length int) string {
	// secretRunes is all runes which may be used in a valid RandomSecret.
	secretRunes := []rune{}
	for _, r := range allRunes {
		secretRunes = append(secretRunes, r...)
	}

	rand.Seed(time.Now().UnixNano())

	bytes := make([]rune, length)

	for i := range bytes {
		bytes[i] = secretRunes[rand.Intn(len(secretRunes))]
	}

	return string(bytes)
}

// UrlSafeRandomSecret generates a RandomSecret and returns it with url-safe encoding.
func UrlSafeRandomSecret(l int) string {
	return url.QueryEscape(RandomSecret(l))
}
