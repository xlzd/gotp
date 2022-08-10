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

	s2 := BuildUri(
		"hotp",
		"XXSZLCRO4S62BZNF",
		"mergenchik@gmail.com",
		"github.com",
		"sha1",
		0,
		6,
		0)
	expected2 := "otpauth://hotp/github.com:mergenchik@gmail.com?counter=0&issuer=github.com&secret=XXSZLCRO4S62BZNF"
	if s2 != expected2 {
		t.Errorf("BuildUri test failed.\n\texpected: %s,\n\tactual: %s", expected2, s2)
	}
}

func TestITob(t *testing.T) {
	var i int64 = 1524486261
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

func TestIsSecretValid(t *testing.T) {
	valid := RandomSecret(64)
	if !IsSecretValid(valid) {
		t.Error("IsSecretValid error - RandomSecret(64) is not valid")
	}
	invalid := "asdsada"
	if IsSecretValid(invalid) {
		t.Error("IsSecretValid error - Bad secret is valid")
	}
}
