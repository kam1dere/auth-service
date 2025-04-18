package secure

import (
	"errors"
	"regexp"
	"strings"
)

const PasswordValidateErr = "Should be 8 characters long and contain a-z, A-Z, 0-9 and a symbol %^&*()_+=;':”,.<>/?"

func IsValidPassword(password string) (bool, error) {

	if len(password) < 8 || len(password) > 30 {
		return false, errors.New(PasswordValidateErr)
	}

	match, err := regexp.MatchString("[0-9]", password)
	if err != nil || !match {
		return false, errors.New(PasswordValidateErr)
	}

	match, err = regexp.MatchString("[A-Z]", password)
	if err != nil || !match {
		return false, errors.New(PasswordValidateErr)
	}

	match, err = regexp.MatchString("[a-z]", password)
	if err != nil || !match {
		return false, errors.New(PasswordValidateErr)
	}

	if !strings.ContainsAny(password, "%^&*()_+=;':”,.<>/?") {
		return false, errors.New(PasswordValidateErr)
	}

	return true, nil
}
