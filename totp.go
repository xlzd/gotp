package gotp

import "time"

// time-based OTP counters.
type TOTP struct {
	OTP
	interval int64
}

func NewTOTP(secret string, digits int, interval int64, hasher *Hasher) *TOTP {
	otp := NewOTP(secret, digits, hasher)
	return &TOTP{OTP: otp, interval: interval}
}

func NewDefaultTOTP(secret string) *TOTP {
	return NewTOTP(secret, 6, 30, nil)
}

// Generate time OTP of given timestamp
func (t *TOTP) At(timestamp int64) string {
	return t.generateOTP(t.timecode(timestamp))
}

func (t *TOTP) AtTime(timestamp time.Time) string {
	return t.At(timestamp.Unix())
}

// Generate the current time OTP
func (t *TOTP) Now() string {
	return t.At(currentTimestamp())
}

// Generate the current time OTP and expiration time
func (t *TOTP) NowWithExpiration() (string, int64) {
	interval64 := int64(t.interval)
	timeCodeInt64 := time.Now().Unix() / interval64
	expirationTime := (timeCodeInt64 + 1) * interval64
	return t.generateOTP(timeCodeInt64), expirationTime
}

/*
Verify OTP.

params:
    otp:         the OTP to check against
    timestamp:   time to check OTP at
*/
func (t *TOTP) Verify(otp string, timestamp int64) bool {
	return otp == t.At(timestamp)
}

func (t *TOTP) VerifyTime(otp string, timestamp time.Time) bool {
	return t.Verify(otp, timestamp.Unix())
}

/*
Returns the provisioning URI for the OTP.
This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.

See also:
    https://github.com/google/google-authenticator/wiki/Key-Uri-Format

params:
    accountName: name of the account
    issuerName:  the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator

returns: provisioning URI
*/
func (t *TOTP) ProvisioningUri(accountName, issuerName string) string {
	return BuildUri(
		OtpTypeTotp,
		t.secret,
		accountName,
		issuerName,
		t.hasher.HashName,
		0,
		t.digits,
		t.interval)
}

func (t *TOTP) timecode(timestamp int64) int64 {
	return int64(timestamp / t.interval)
}
