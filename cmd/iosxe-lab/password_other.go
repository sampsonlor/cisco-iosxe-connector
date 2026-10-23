//go:build !windows

package main

import "errors"

func promptPassword(string, string) (string, error) {
	return "", errors.New("this password dialog requires Windows")
}
