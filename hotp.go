package gotp

// HMAC-based OTP counters.
type HOTP struct {
	OTP
}

func NewHOTP(secret string, digits int, hasher *Hasher) *HOTP {
	otp := NewOTP(secret, digits, hasher)
	return &HOTP{OTP: otp}

}

func NewDefaultHOTP(secret string) *HOTP {
	return NewHOTP(secret, 6, nil)
}

// Generates the OTP for the given count.
func (h *HOTP) At(count int) string {
	return h.generateOTP(int64(count))
}

/*
Verify OTP.

params:
    otp:   the OTP to check against
    count: the OTP HMAC counter
*/
func (h *HOTP) Verify(otp string, count int) bool {
	return otp == h.At(count)
}

/*
Returns the provisioning URI for the OTP.
This can then be encoded in a QR Code and used to provision an OTP app like Google Authenticator.

See also:
    https://github.com/google/google-authenticator/wiki/Key-Uri-Format

params:
    accountName:  name of the account
    issuerName:   the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator
    initialCount: starting HMAC counter value

returns: provisioning URI
*/
func (h *HOTP) ProvisioningUri(accountName, issuerName string, initialCount int) string {
	return BuildUri(
		OtpTypeHotp,
		h.secret,
		accountName,
		issuerName,
		h.hasher.HashName,
		initialCount,
		h.digits,
		0)
}
