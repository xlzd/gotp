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
	expected := "otpauth://totp/SomeOrg:xlzd?issuer=SomeOrg&secret=4S62BZNFXXSZLCRO"
	if s != expected {
		t.Errorf("BuildUri test failed.\n\texpected: %s,\n\tactual: %s", expected, s)
	}
}

func TestITob(t *testing.T) {
	i := 1524486261
	expect := []byte{0, 0, 0, 0, 90, 221, 208, 117}

	if string(expect) != string(Itob(i)) {
		t.Error("ITob error")
	}
}

func TestRandomSecret(t *testing.T) {
	secret := RandomSecret(64)
	if len(secret) == 0 {
		t.Error("RandomSecret error")
	}
}