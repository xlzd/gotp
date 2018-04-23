package gotp

import (
	"testing"
)

func TestBuildUri(t *testing.T) {
	s := BuildUri(
		"totp",
		"4S62BZNFXXSZLCRO",
		"xlzd",
		"SomeOrg",
		"sha1",
		0,
		6,
		0,
	)
	if s != "otpauth://totp/SomeOrg:xlzd?secret=4S62BZNFXXSZLCRO&issuer=SomeOrg" {
		t.Error("BuildUri test failed")
	}
}

func TestITob(t *testing.T) {
	i := 1524486261
	expect := []byte{0, 0, 0, 0, 90, 221, 208, 117}

	if string(expect) != string(Itob(i)) {
		t.Error("ITob error")
	}
}
