// File: golang/types_test.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall_test

import (
	"errors"
	"testing"

	ucall "github.com/unum-cloud/ucall/golang"
)

func TestNamesRoundTrip(t *testing.T) {
	status, err := ucall.StatusFromName(ucall.StatusConnectionFailed.String())
	if err != nil || status != ucall.StatusConnectionFailed {
		t.Fatalf("status %v, error %v", status, err)
	}
	if _, err := ucall.StatusFromName("no-such-status"); !errors.Is(err, ucall.StatusInvalidArgument) {
		t.Fatalf("an unknown status name answered %v", err)
	}
	backend, err := ucall.BackendFromName(ucall.BackendPOSIX.String())
	if err != nil || backend != ucall.BackendPOSIX {
		t.Fatalf("backend %v, error %v", backend, err)
	}
	class, err := ucall.CPUClassFromName(ucall.CPUClassSerial.String())
	if err != nil || class != ucall.CPUClassSerial {
		t.Fatalf("class %v, error %v", class, err)
	}
	if ucall.Version() == "" {
		t.Fatal("the library has no version")
	}
}

func TestNoiseKeysDeriveBack(t *testing.T) {
	privateKey, publicKey, err := ucall.GenerateNoiseKeypair()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := ucall.DeriveNoisePublicKey(privateKey)
	if err != nil || derived != publicKey {
		t.Fatalf("derived %x, generated %x, error %v", derived, publicKey, err)
	}
}

func TestDecodePercent(t *testing.T) {
	decoded, err := ucall.DecodePercent([]byte("a%20b+c"), ucall.PercentQuery)
	if err != nil || string(decoded) != "a b c" {
		t.Fatalf("decoded %q, error %v", decoded, err)
	}
	if _, err := ucall.DecodePercent([]byte("%zz"), ucall.PercentPath); !errors.Is(err, ucall.StatusInvalidArgument) {
		t.Fatalf("a malformed escape answered %v", err)
	}
}
