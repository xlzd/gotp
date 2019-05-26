package gotp

import (
	"testing"
)

var totp = NewDefaultTOTP("4S62BZNFXXSZLCRO")

func TestTOTP_At(t *testing.T) {
	if totp.Now() != totp.At(currentTimestamp()) {
		t.Error("TOTP generate otp error!")
	}
}

func TestTOTP_NowWithExpiration(t *testing.T) {
	otp, exp := totp.NowWithExpiration()
	cts := currentTimestamp()
	if otp != totp.Now() {
		t.Error("TOTP generate otp error!")
	}
	if totp.At(cts+30) != totp.At(int(exp)) {
		t.Error("TOTP expiration otp error!")
	}
}

func TestTOTP_Verify(t *testing.T) {
	if !totp.Verify("179394", 1524485781) {
		t.Error("verify faild")
	}
}

func TestTOTP_ProvisioningUri(t *testing.T) {
	expect := "otpauth://totp/github:xlzd?secret=4S62BZNFXXSZLCRO&issuer=github"
	uri := totp.ProvisioningUri("xlzd", "github")
	if expect != uri {
		t.Error("ProvisioningUri error")
	}
}

func TestTOTP_NowWithExpirationHex(t *testing.T) {
	otpHex := NewTOTP("4S62BZNFXXSZLCRO", 6, 30, nil, FormatHex)
	otp, exp := otpHex.NowWithExpiration()
	cts := currentTimestamp()
	if otp != otpHex.Now() {
		t.Error("TOTP hex generate otp error!")
	}
	if totp.At(cts+30) != totp.At(int(exp)) {
		t.Error("TOTP hex expiration otp error!")
	}
}
