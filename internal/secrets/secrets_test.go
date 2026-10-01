package secrets

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func testManager(t *testing.T, m Manager) {
	t.Helper()
	if _, err := m.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing: err = %v, want ErrNotFound", err)
	}
	if err := m.Delete("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing: err = %v, want ErrNotFound", err)
	}
	if err := m.Set("a", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Set("a", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, err := m.Get("a"); err != nil || v != "v2" {
		t.Errorf("Get = %q, %v; want v2", v, err)
	}
	if err := m.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
}

func TestMemory(t *testing.T) { testManager(t, Memory{}) }

func TestKeyring(t *testing.T) {
	keyring.MockInit() // in-memory backend; doesn't touch the real keychain
	testManager(t, Keyring{})
}
