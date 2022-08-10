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
	if totp.At(cts+30) != totp.At(exp) {
		t.Error("TOTP expiration otp error!")
	}
}

func TestTOTP_Verify(t *testing.T) {
	if !totp.Verify("179394", 1524485781) {
		t.Error("verify faild")
	}
}

func TestTOTP_ProvisioningUri(t *testing.T) {
	expect := "otpauth://totp/github:xlzd?issuer=github&secret=4S62BZNFXXSZLCRO"
	uri := totp.ProvisioningUri("xlzd", "github")
	if expect != uri {
		t.Errorf("ProvisioningUri error.\n\texpected: %s,\n\tactual: %s", expect, uri)
	}
}
