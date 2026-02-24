package secret

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

const service = "authbear"

func Set(key, value string) error {
	if err := keyring.Set(service, key, value); err != nil {
		return fmt.Errorf("set keychain secret %q: %w", key, err)
	}
	return nil
}

func Get(key string) (string, error) {
	v, err := keyring.Get(service, key)
	if err != nil {
		return "", fmt.Errorf("get keychain secret %q: %w", key, err)
	}
	return v, nil
}

func Delete(key string) error {
	err := keyring.Delete(service, key)
	if err == keyring.ErrNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete keychain secret %q: %w", key, err)
	}
	return nil
}
