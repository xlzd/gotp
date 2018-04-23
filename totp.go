package gotp

// time-based OTP counters.
type TOTP struct {
	OTP
	interval int
}

func NewTOTP(secret string, digits, interval int, hasher *Hasher) *TOTP {
	otp := NewOTP(secret, digits, hasher)
	return &TOTP{OTP: otp, interval: interval}
}

func NewDefaultTOTP(secret string) *TOTP {
	return NewTOTP(secret, 6, 30, nil)
}

// Generate time OTP of given timestamp
func (t *TOTP) At(timestamp int) string {
	return t.generateOTP(t.timecode(timestamp))
}

// Generate the current time OTP
func (t *TOTP) Now() string {
	return t.At(currentTimestamp())
}

/*
Verify OTP.

params:
    otp:         the OTP to check against
    timestamp:   time to check OTP at
*/
func (t *TOTP) Verify(otp string, timestamp int) bool {
	return otp == t.At(timestamp)
}

/*
Returns the provisioning URI for the OTP.
This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.

See also:
    https://github.com/google/google-authenticator/wiki/Key-Uri-Format

params:
    name:       name of the account
    issuerName: the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator

returns: provisioning URI
*/
func (t *TOTP) ProvisioningUri(name, issuerName string) string {
	return BuildUri(
		OtpTypeTotp,
		t.secret,
		name,
		issuerName,
		t.hasher.HashName,
		0,
		t.digits,
		t.interval)
}

func (t *TOTP) timecode(timestamp int) int {
	return int(timestamp / t.interval)
}
