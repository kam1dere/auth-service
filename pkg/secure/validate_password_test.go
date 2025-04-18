package secure

import (
	"testing"
)

func TestIsValidPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{
			name:     "Too short",
			password: "Ab1$",
			valid:    false,
		},
		{
			name:     "Too long",
			password: "Averylongpasswordwithmorethanthirtycharacters1$",
			valid:    false,
		},
		{
			name:     "Missing digit",
			password: "Password!@",
			valid:    false,
		},
		{
			name:     "Missing uppercase",
			password: "password1!@",
			valid:    false,
		},
		{
			name:     "Missing lowercase",
			password: "PASSWORD1!@",
			valid:    false,
		},
		{
			name:     "Missing symbol",
			password: "Password1",
			valid:    false,
		},
		{
			name:     "Valid password",
			password: "ValidPass1=",
			valid:    true,
		},
		{
			name:     "Edge case exactly 8",
			password: "Aa1%aaaA", // 8 символов, содержит цифру, верхний и нижний регистр, символ
			valid:    true,
		},
		{
			name:     "Edge case exactly 30",
			password: "Aa1%aaaaaaaaaaaaaaaaaaaaaaAAA", // 30 символов, пример
			valid:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isValid, err := IsValidPassword(tc.password)
			if isValid != tc.valid {
				t.Errorf("expected valid=%v, got valid=%v; err=%v", tc.valid, isValid, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected an error for invalid password, got nil")
			}
			if !tc.valid && err != nil && err.Error() != PasswordValidateErr {
				t.Errorf("expected error message %q, got %q", PasswordValidateErr, err.Error())
			}
		})
	}
}
