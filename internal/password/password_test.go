package password

import (
	"strings"
	"testing"
)

func TestSaltAndVerification(t *testing.T) {
	a, err := Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || strings.Contains(a, "sufficiently") {
		t.Fatal("hashes need individual salts and cannot contain the password")
	}
	if !Verify(a, "a sufficiently long password") || Verify(a, "wrong password") {
		t.Fatal("incorrect verification")
	}
}

func TestMalformedHashesFailClosed(t *testing.T) {
	for _, encoded := range []string{"", "plaintext", "$argon2id$v=19$m=1,t=1,p=1$YWJj$YWJj", "$argon2id$v=19$m=4294967295,t=999,p=1$YWJj$YWJj"} {
		if Verify(encoded, "password") {
			t.Errorf("accepted %q", encoded)
		}
	}
}
