// Package secrets provides named credential storage.
package secrets

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

var ErrNotFound = errors.New("secret not found")

// Store looks up secrets by name.
type Store interface {
	// Get returns the secret's value, or an error wrapping ErrNotFound.
	Get(name string) (string, error)
}

// Manager is a Store that can also be modified.
type Manager interface {
	Store
	Set(name, value string) error
	// Delete removes the secret, or returns an error wrapping ErrNotFound.
	Delete(name string) error
}

// KeyringService is the OS keychain service name pcp stores secrets under.
const KeyringService = "pcp"

// Keyring stores secrets in the OS keychain (macOS Keychain, Linux Secret
// Service, Windows Credential Manager).
type Keyring struct{}

func (Keyring) Get(name string) (string, error) {
	v, err := keyring.Get(KeyringService, name)
	return v, wrapKeyringErr(name, err)
}

func (Keyring) Set(name, value string) error {
	return wrapKeyringErr(name, keyring.Set(KeyringService, name, value))
}

func (Keyring) Delete(name string) error {
	return wrapKeyringErr(name, keyring.Delete(KeyringService, name))
}

func wrapKeyringErr(name string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	default:
		return fmt.Errorf("keychain: %w", err)
	}
}

// Memory is an in-memory Manager, mainly for tests.
type Memory map[string]string

func (m Memory) Get(name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return v, nil
}

func (m Memory) Set(name, value string) error {
	m[name] = value
	return nil
}

func (m Memory) Delete(name string) error {
	if _, ok := m[name]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	delete(m, name)
	return nil
}
