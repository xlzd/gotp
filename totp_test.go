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
