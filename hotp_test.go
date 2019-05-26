package gotp

import (
	"testing"
)

var hotp = NewDefaultHOTP("4S62BZNFXXSZLCRO")

func TestHOTP_At(t *testing.T) {
	otp := hotp.At(12345)
	if "194001" != otp {
		t.Error("HOTP generate otp error")
	}
}

func TestHOTP_Verify(t *testing.T) {
	if !hotp.Verify("194001", 12345) {
		t.Error("verify faild")
	}
}

func TestHOTP_Hex(t *testing.T) {
	otpHex := NewHOTP("4S62BZNFXXSZLCRO", 6, nil, FormatHex)
	otp := otpHex.At(12345)
	if "02f5d1" != otp {
		t.Errorf("HOTP generate otp error: %v", otp)
	}
}
