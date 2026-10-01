// Package secrets provides named credential storage.
package secrets

import "errors"

var ErrNotFound = errors.New("secret not found")

// Store looks up secrets by name.
type Store interface {
	// Get returns the secret's value, or an error wrapping ErrNotFound.
	Get(name string) (string, error)
}

// Memory is an in-memory Store, mainly for tests.
type Memory map[string]string

func (m Memory) Get(name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
